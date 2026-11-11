// Package llm provides an OpenAI-compatible chat client used by the operator
// backend's AI conversation and template-generation module. It works with any
// OpenAI-compatible endpoint (DeepSeek, OpenAI, Moonshot, local vLLM, etc.).
package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ToolCall is one function invocation requested by the model.
type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type,omitempty"` // "function"
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ToolFunction describes one callable tool to the provider.
type ToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// Tool is an OpenAI-compatible function tool definition.
type Tool struct {
	Type     string       `json:"type"` // "function"
	Function ToolFunction `json:"function"`
}

// ContentPart is one element of a multimodal message.
type ContentPart struct {
	Type     string    `json:"type"` // "text" | "image_url"
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

// ImageURL is an image content part; URL may be a data: URL.
type ImageURL struct {
	URL string `json:"url"`
}

// Message is one chat turn. ToolCalls is set on assistant turns that asked for
// tools; ToolCallID/Name are set on the "tool" turns carrying the results.
// Images is provider-facing only (data URLs or https URLs); it is never
// persisted in chat history.
type Message struct {
	Role       string     `json:"role"` // "system" | "user" | "assistant" | "tool"
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
	Images     []string   `json:"-"`
}

// UnmarshalJSON accepts both a plain string and an array content, so providers
// that reply with content parts (multimodal) can be decoded.
func (m *Message) UnmarshalJSON(data []byte) error {
	type wire struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content"`
		ToolCalls  []ToolCall      `json:"tool_calls"`
		ToolCallID string          `json:"tool_call_id"`
		Name       string          `json:"name"`
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	m.Role, m.ToolCalls, m.ToolCallID, m.Name = w.Role, w.ToolCalls, w.ToolCallID, w.Name
	if len(w.Content) == 0 || string(w.Content) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(w.Content, &s); err == nil {
		m.Content = s
		return nil
	}
	var parts []ContentPart
	if err := json.Unmarshal(w.Content, &parts); err == nil {
		var b strings.Builder
		for _, p := range parts {
			if p.Type == "text" {
				b.WriteString(p.Text)
			}
		}
		m.Content = b.String()
		return nil
	}
	m.Content = string(w.Content)
	return nil
}

// WireMessages converts messages to the provider wire format, expanding Images
// into OpenAI multimodal content parts. Messages without images are emitted
// unchanged.
func WireMessages(msgs []Message) []any {
	out := make([]any, 0, len(msgs))
	for _, m := range msgs {
		if len(m.Images) == 0 {
			out = append(out, m)
			continue
		}
		parts := make([]ContentPart, 0, len(m.Images)+1)
		if m.Content != "" {
			parts = append(parts, ContentPart{Type: "text", Text: m.Content})
		}
		for _, u := range m.Images {
			if u != "" {
				parts = append(parts, ContentPart{Type: "image_url", ImageURL: &ImageURL{URL: u}})
			}
		}
		out = append(out, map[string]any{"role": m.Role, "content": parts})
	}
	return out
}

// HasImages reports whether any message carries an image part.
func HasImages(msgs []Message) bool {
	for _, m := range msgs {
		if len(m.Images) > 0 {
			return true
		}
	}
	return false
}

// StripImages returns a copy of msgs with all image parts removed, used when a
// provider rejects multimodal input.
func StripImages(msgs []Message) []Message {
	out := make([]Message, len(msgs))
	for i, m := range msgs {
		if len(m.Images) > 0 {
			m.Images = nil
		}
		out[i] = m
	}
	return out
}

// ChatResult is one non-streamed-by-the-caller completion, including any tool
// calls the model requested.
type ChatResult struct {
	Content      string
	Usage        Usage
	ToolCalls    []ToolCall
	FinishReason string
}

// Client talks to an OpenAI-compatible chat endpoint.
type Client struct {
	BaseURL string
	Key     string
	Model   string
	// Temperature is the sampling temperature sent with every request. New
	// defaults it to 0.7; 0 is a valid (deterministic) value.
	Temperature float64
	HTTP        *http.Client

	modelsMu   sync.Mutex
	modelsList []string
	modelsAt   time.Time
}

// modelsTTL is how long a provider's model list is reused before asking again.
const modelsTTL = 10 * time.Minute

// modelsHTTP is used only for the best-effort /models probe, so a slow or
// unreachable provider cannot block the console for the full chat timeout.
var modelsHTTP = &http.Client{Timeout: 5 * time.Second}

// streamHTTP has no overall timeout: a streaming answer may legitimately run
// for minutes. Callers bound it with a context instead.
var streamHTTP = &http.Client{}

// retryable reports whether an HTTP status is worth retrying.
func retryable(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// ValidateBaseURL checks that raw is an absolute http(s) URL.
func ValidateBaseURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("base_url 不是合法 URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("base_url 必须以 http:// 或 https:// 开头")
	}
	if u.Host == "" {
		return fmt.Errorf("base_url 缺少主机名")
	}
	return nil
}

// applyAuth sets the provider credential header. Azure OpenAI expects
// "api-key" rather than a Bearer token; both are never sent together.
func (c *Client) applyAuth(req *http.Request) {
	if c.Key == "" {
		return
	}
	if strings.HasSuffix(strings.ToLower(req.URL.Hostname()), ".openai.azure.com") {
		req.Header.Set("api-key", c.Key)
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
}

// New builds a client. baseURL is the API root (e.g. https://api.deepseek.com/v1).
func New(baseURL, key, model string) *Client {
	return &Client{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		Key:         key,
		Model:       model,
		Temperature: 0.7,
		HTTP:        &http.Client{Timeout: 120 * time.Second},
	}
}

// Available reports whether the client is configured for real calls. The key
// is optional: local OpenAI-compatible servers (Ollama, vLLM, …) usually do
// not check it, and a missing key on a hosted provider simply surfaces the
// provider's own 401 instead of a misleading "not configured" error.
func (c *Client) Available() bool {
	return c != nil && c.BaseURL != ""
}

type chatReq struct {
	Model         string         `json:"model"`
	Messages      []any          `json:"messages"`
	Temperature   float64        `json:"temperature"`
	Stream        bool           `json:"stream,omitempty"`
	StreamOptions *streamOptions `json:"stream_options,omitempty"`
	Tools         []Tool         `json:"tools,omitempty"`
	// ToolChoice is "auto" (default) or "none". The console never forces a
	// specific function; the model decides.
	ToolChoice string `json:"tool_choice,omitempty"`
}

type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// retryBackoff returns the delay before retry attempt n (0-based).
func retryBackoff(attempt int) time.Duration {
	return time.Duration(400*(1<<attempt)) * time.Millisecond
}

// sleepCtx waits d or until the context is done.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Usage is the token accounting returned by the provider.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type chatResp struct {
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
	} `json:"choices"`
	Usage Usage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Chat sends the conversation and returns the assistant's reply plus the token
// usage.
func (c *Client) Chat(model string, messages []Message) (string, Usage, error) {
	if !c.Available() {
		return "", Usage{}, fmt.Errorf("LLM 未配置：请在后台「AI 对话」页填写 Base URL 与 API Key，或设置 PHISH_LLM_BASE_URL")
	}
	if model == "" {
		model = c.Model
	}
	body, err := json.Marshal(chatReq{Model: model, Messages: WireMessages(messages), Temperature: c.Temperature})
	if err != nil {
		return "", Usage{}, err
	}
	newReq := func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		c.applyAuth(req)
		return req, nil
	}

	// Transient provider failures (429/5xx/network) get two quick retries; a
	// request body is never reused across attempts.
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		req, err := newReq()
		if err != nil {
			return "", Usage{}, err
		}
		resp, err = c.HTTP.Do(req)
		if err != nil {
			if attempt < 2 {
				time.Sleep(retryBackoff(attempt))
				continue
			}
			return "", Usage{}, fmt.Errorf("调用 LLM 失败: %w", err)
		}
		if retryable(resp.StatusCode) && attempt < 2 {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			time.Sleep(retryBackoff(attempt))
			continue
		}
		break
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	var cr chatResp
	if err := json.Unmarshal(data, &cr); err != nil {
		return "", Usage{}, fmt.Errorf("解析 LLM 响应失败 (HTTP %d): %s", resp.StatusCode, truncate(string(data), 400))
	}
	if cr.Error != nil && cr.Error.Message != "" {
		return "", Usage{}, fmt.Errorf("LLM 返回错误: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 || cr.Choices[0].Message.Content == "" {
		return "", Usage{}, fmt.Errorf("LLM 未返回内容 (HTTP %d)", resp.StatusCode)
	}
	// A "length" stop means the provider cut the answer at max_tokens. Treat
	// the partial output as a failure: a truncated landing page or email is
	// worse than a clear error the operator can retry with a shorter prompt.
	if cr.Choices[0].FinishReason == "length" {
		return "", Usage{}, fmt.Errorf("LLM 输出被截断（达到模型 max_tokens 上限），请缩短输入或换用输出上限更大的模型")
	}
	return cr.Choices[0].Message.Content, cr.Usage, nil
}

type streamToolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type streamChunk struct {
	Choices []struct {
		Delta struct {
			Content   string           `json:"content"`
			ToolCalls []streamToolCall `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *Usage `json:"usage,omitempty"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// ChatStream sends the conversation and streams the assistant's reply through
// onDelta as it arrives. It returns the full reply and the token usage the
// provider reported (if any). The response body is closed when it returns; the
// caller bounds the call with ctx.
func (c *Client) ChatStream(ctx context.Context, model string, messages []Message, onDelta func(string) error) (string, Usage, error) {
	res, err := c.ChatWithTools(ctx, model, messages, nil, onDelta)
	return res.Content, res.Usage, err
}

// ChatWithTools is ChatStream plus OpenAI-compatible function calling. Text
// deltas are passed to onDelta as they arrive; tool-call fragments are
// accumulated and returned once the stream ends. It returns an error for a
// truncated (finish_reason "length") or empty answer.
func (c *Client) ChatWithTools(ctx context.Context, model string, messages []Message, tools []Tool, onDelta func(string) error) (ChatResult, error) {
	var out ChatResult
	if !c.Available() {
		return out, fmt.Errorf("LLM 未配置：请在后台「AI 对话」页填写 Base URL 与 API Key，或设置 PHISH_LLM_BASE_URL")
	}
	if model == "" {
		model = c.Model
	}
	body, err := json.Marshal(chatReq{
		Model:         model,
		Messages:      WireMessages(messages),
		Temperature:   c.Temperature,
		Stream:        true,
		StreamOptions: &streamOptions{IncludeUsage: true},
		Tools:         tools,
	})
	if err != nil {
		return out, err
	}
	newReq := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/event-stream")
		c.applyAuth(req)
		return req, nil
	}

	// Transient failures before the stream starts (network, 429, 5xx) are safe
	// to retry: no delta has reached the caller yet. Once streaming begins a
	// retry would duplicate text, so the loop stops at the first response.
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		req, rerr := newReq()
		if rerr != nil {
			return out, rerr
		}
		resp, rerr = streamHTTP.Do(req)
		if rerr != nil {
			if attempt < 2 && ctx.Err() == nil {
				if serr := sleepCtx(ctx, retryBackoff(attempt)); serr != nil {
					return out, fmt.Errorf("调用 LLM 失败: %w", rerr)
				}
				continue
			}
			return out, fmt.Errorf("调用 LLM 失败: %w", rerr)
		}
		if retryable(resp.StatusCode) && attempt < 2 {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if serr := sleepCtx(ctx, retryBackoff(attempt)); serr != nil {
				return out, fmt.Errorf("调用 LLM 失败: %w", serr)
			}
			continue
		}
		break
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var cr chatResp
		if err := json.Unmarshal(data, &cr); err == nil && cr.Error != nil && cr.Error.Message != "" {
			return out, fmt.Errorf("LLM 返回错误: %s", cr.Error.Message)
		}
		return out, fmt.Errorf("LLM 返回错误 (HTTP %d): %s", resp.StatusCode, truncate(string(data), 400))
	}

	var reply strings.Builder
	acc := map[int]*ToolCall{}
	var usage Usage
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			break
		}
		var ch streamChunk
		if err := json.Unmarshal([]byte(payload), &ch); err != nil {
			continue // tolerate keep-alive/comment payloads
		}
		if ch.Error != nil && ch.Error.Message != "" {
			out.Content = reply.String()
			return out, fmt.Errorf("LLM 返回错误: %s", ch.Error.Message)
		}
		if ch.Usage != nil {
			usage = *ch.Usage
		}
		for _, choice := range ch.Choices {
			for _, frag := range choice.Delta.ToolCalls {
				idx := frag.Index
				if idx < 0 {
					idx = 0
				}
				tc := acc[idx]
				if tc == nil {
					tc = &ToolCall{Type: "function"}
					acc[idx] = tc
				}
				if frag.ID != "" {
					tc.ID = frag.ID
				}
				if frag.Type != "" {
					tc.Type = frag.Type
				}
				if frag.Function.Name != "" {
					tc.Function.Name = frag.Function.Name
				}
				tc.Function.Arguments += frag.Function.Arguments
			}
			if choice.Delta.Content != "" {
				reply.WriteString(choice.Delta.Content)
				if onDelta != nil {
					if err := onDelta(choice.Delta.Content); err != nil {
						out.Content = reply.String()
						out.Usage = usage
						return out, err
					}
				}
			}
			if choice.FinishReason == "length" {
				out.Content = reply.String()
				out.Usage = usage
				return out, fmt.Errorf("LLM 输出被截断（达到模型 max_tokens 上限），请缩短输入或换用输出上限更大的模型")
			}
			if choice.FinishReason != "" {
				out.FinishReason = choice.FinishReason
			}
		}
	}
	if err := sc.Err(); err != nil {
		out.Content = reply.String()
		out.Usage = usage
		return out, fmt.Errorf("读取 LLM 流失败: %w", err)
	}
	out.Content = reply.String()
	out.Usage = usage
	if len(acc) > 0 {
		idxs := make([]int, 0, len(acc))
		for i := range acc {
			idxs = append(idxs, i)
		}
		sort.Ints(idxs)
		for _, i := range idxs {
			tc := acc[i]
			if tc.Function.Name == "" {
				continue // incomplete fragment; nothing callable
			}
			if tc.ID == "" {
				tc.ID = fmt.Sprintf("call_%d_%d", time.Now().UnixNano(), i)
			}
			out.ToolCalls = append(out.ToolCalls, *tc)
		}
	}
	if out.Content == "" && len(out.ToolCalls) == 0 {
		return out, fmt.Errorf("LLM 未返回内容")
	}
	return out, nil
}

type modelListResp struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// Models returns the model ids advertised by the provider, or the fallback list
// when the provider is unreachable or unconfigured. Successful results are
// cached for modelsTTL so the console does not wait on the provider on every
// page load.
func (c *Client) Models(fallback []string) []string {
	if !c.Available() {
		return fallback
	}
	c.modelsMu.Lock()
	if len(c.modelsList) > 0 && time.Since(c.modelsAt) < modelsTTL {
		cached := append([]string(nil), c.modelsList...)
		c.modelsMu.Unlock()
		return cached
	}
	c.modelsMu.Unlock()

	req, err := http.NewRequest(http.MethodGet, c.BaseURL+"/models", nil)
	if err != nil {
		return fallback
	}
	c.applyAuth(req)
	resp, err := modelsHTTP.Do(req)
	if err != nil {
		return fallback
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fallback
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var ml modelListResp
	if err := json.Unmarshal(data, &ml); err != nil || len(ml.Data) == 0 {
		return fallback
	}
	out := make([]string, 0, len(ml.Data))
	for _, m := range ml.Data {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	c.modelsMu.Lock()
	c.modelsList = append([]string(nil), out...)
	c.modelsAt = time.Now()
	c.modelsMu.Unlock()
	return out
}

// truncate shortens s to at most n runes without splitting a UTF-8 character.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// RefreshModels force-fetches the provider's model list using the current key.
// Unlike Models it returns the provider error instead of a fallback.
func (c *Client) RefreshModels(ctx context.Context) ([]string, error) {
	if c == nil || c.BaseURL == "" {
		return nil, fmt.Errorf("LLM 未配置 Base URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/models", nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req)
	resp, err := modelsHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("模型接口返回 %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	out := []string{}
	var ml modelListResp
	if json.Unmarshal(data, &ml) == nil {
		for _, m := range ml.Data {
			if m.ID != "" {
				out = append(out, m.ID)
			}
		}
	}
	if len(out) == 0 {
		var alt struct {
			Models []string `json:"models"`
		}
		if json.Unmarshal(data, &alt) == nil {
			out = append(out, alt.Models...)
		}
	}
	if len(out) == 0 {
		var arr []string
		if json.Unmarshal(data, &arr) == nil {
			out = append(out, arr...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("模型接口没有返回模型列表: %s", truncate(string(data), 200))
	}
	c.modelsMu.Lock()
	c.modelsList = append([]string(nil), out...)
	c.modelsAt = time.Now()
	c.modelsMu.Unlock()
	return out, nil
}
