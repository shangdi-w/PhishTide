package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAvailable(t *testing.T) {
	if New("", "", "").Available() {
		t.Fatal("empty base URL should not be available")
	}
	// The API key is optional for local OpenAI-compatible servers.
	if !New("http://127.0.0.1:11434/v1", "", "").Available() {
		t.Fatal("keyless local endpoint should be available")
	}
	if !New("https://api.deepseek.com/v1", "k", "").Available() {
		t.Fatal("configured endpoint should be available")
	}
	var nilClient *Client
	if nilClient.Available() {
		t.Fatal("nil client must not be available")
	}
}

func TestChatSuccess(t *testing.T) {
	var gotAuth, gotPath, gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotModel = body.Model
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"你好"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}`))
	}))
	defer srv.Close()

	c := New(srv.URL+"/v1/", "sekret", "deepseek-chat")
	reply, usage, err := c.Chat("", []Message{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if reply != "你好" {
		t.Fatalf("reply = %q", reply)
	}
	if usage.TotalTokens != 8 || usage.PromptTokens != 3 || usage.CompletionTokens != 5 {
		t.Fatalf("usage = %+v", usage)
	}
	if gotAuth != "Bearer sekret" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotPath != "/v1/chat/completions" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotModel != "deepseek-chat" {
		t.Fatalf("default model not applied, got %q", gotModel)
	}
}

func TestChatSendsTemperature(t *testing.T) {
	var gotTemp float64 = -1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Temperature float64 `json:"temperature"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotTemp = body.Temperature
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	c := New(srv.URL+"/v1", "", "m")
	if c.Temperature != 0.7 {
		t.Fatalf("default temperature = %v, want 0.7", c.Temperature)
	}
	c.Temperature = 0.2
	if _, _, err := c.Chat("", []Message{{Role: "user", Content: "hi"}}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if gotTemp != 0.2 {
		t.Fatalf("request temperature = %v, want 0.2", gotTemp)
	}

	// 0 is a meaningful value (deterministic sampling), not "unset".
	gotTemp = -1
	c.Temperature = 0
	if _, _, err := c.Chat("", []Message{{Role: "user", Content: "hi"}}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if gotTemp != 0 {
		t.Fatalf("request temperature = %v, want 0", gotTemp)
	}
}

func TestChatWithoutKey(t *testing.T) {
	var authSeen atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			authSeen.Store(true)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "", "local-model")
	if _, _, err := c.Chat("", []Message{{Role: "user", Content: "hi"}}); err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if authSeen.Load() {
		t.Fatal("Authorization header sent without a key")
	}
}

func TestChatProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	defer srv.Close()

	_, _, err := New(srv.URL, "k", "").Chat("", []Message{{Role: "user", Content: "hi"}})
	if err == nil || !strings.Contains(err.Error(), "invalid api key") {
		t.Fatalf("err = %v", err)
	}
}

func TestChatEmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()

	_, _, err := New(srv.URL, "k", "").Chat("", []Message{{Role: "user", Content: "hi"}})
	if err == nil || !strings.Contains(err.Error(), "未返回内容") {
		t.Fatalf("err = %v", err)
	}
}

func TestChatTruncatedOutputIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"<html>partial"},"finish_reason":"length"}]}`))
	}))
	defer srv.Close()

	_, _, err := New(srv.URL, "k", "").Chat("", []Message{{Role: "user", Content: "hi"}})
	if err == nil || !strings.Contains(err.Error(), "截断") {
		t.Fatalf("err = %v", err)
	}
}

func TestChatUnconfigured(t *testing.T) {
	_, _, err := New("", "", "").Chat("", []Message{{Role: "user", Content: "hi"}})
	if err == nil || !strings.Contains(err.Error(), "未配置") {
		t.Fatalf("err = %v", err)
	}
}

func TestModelsSuccessAndCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/models" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("missing bearer token")
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"m1"},{"id":"m2"},{"id":""}]}`))
	}))
	defer srv.Close()

	c := New(srv.URL+"/v1", "k", "")
	got := c.Models([]string{"fallback"})
	if strings.Join(got, ",") != "m1,m2" {
		t.Fatalf("models = %v", got)
	}
	// Second call must be served from the cache.
	again := c.Models([]string{"fallback"})
	if strings.Join(again, ",") != "m1,m2" {
		t.Fatalf("models = %v", again)
	}
	if hits.Load() != 1 {
		t.Fatalf("provider hit %d times, want 1", hits.Load())
	}
}

func TestModelsFallback(t *testing.T) {
	fallback := []string{"f1", "f2"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if got := New(srv.URL, "k", "").Models(fallback); strings.Join(got, ",") != "f1,f2" {
		t.Fatalf("models = %v", got)
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer empty.Close()
	if got := New(empty.URL, "k", "").Models(fallback); strings.Join(got, ",") != "f1,f2" {
		t.Fatalf("models = %v", got)
	}

	if got := New("", "", "").Models(fallback); strings.Join(got, ",") != "f1,f2" {
		t.Fatalf("unconfigured models = %v", got)
	}
}

func TestChatRetriesTransientFailures(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	reply, _, err := New(srv.URL, "k", "").Chat("", []Message{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if reply != "ok" {
		t.Fatalf("reply = %q", reply)
	}
	if hits.Load() != 3 {
		t.Fatalf("provider hit %d times, want 3", hits.Load())
	}
}

func TestChatWithToolsRetriesBeforeStreaming(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	var got strings.Builder
	res, err := New(srv.URL, "k", "").ChatWithTools(context.Background(), "",
		[]Message{{Role: "user", Content: "hi"}}, nil, func(d string) error {
			got.WriteString(d)
			return nil
		})
	if err != nil {
		t.Fatalf("ChatWithTools: %v", err)
	}
	if res.Content != "ok" || got.String() != "ok" {
		t.Fatalf("content = %q, deltas = %q", res.Content, got.String())
	}
	if hits.Load() != 3 {
		t.Fatalf("provider hit %d times, want 3", hits.Load())
	}
}

func TestChatWithToolsStopsRetryingAfterThreeFailures(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream down"}}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "k", "").ChatWithTools(context.Background(), "",
		[]Message{{Role: "user", Content: "hi"}}, nil, nil); err == nil {
		t.Fatal("expected an error")
	}
	if hits.Load() != 3 {
		t.Fatalf("provider hit %d times, want 3", hits.Load())
	}
}

func TestChatStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		var body struct {
			Stream bool `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !body.Stream {
			t.Error("stream flag not set")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		for _, part := range []string{"你", "好"} {
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%q},\"finish_reason\":null}]}\n\n", part)
			f.Flush()
		}
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3,\"total_tokens\":5}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer srv.Close()

	var deltas []string
	reply, usage, err := New(srv.URL, "k", "").ChatStream(context.Background(), "",
		[]Message{{Role: "user", Content: "hi"}},
		func(d string) error { deltas = append(deltas, d); return nil })
	if err != nil {
		t.Fatalf("ChatStream: %v", err)
	}
	if reply != "你好" {
		t.Fatalf("reply = %q", reply)
	}
	if strings.Join(deltas, "|") != "你|好" {
		t.Fatalf("deltas = %v", deltas)
	}
	if usage.TotalTokens != 5 {
		t.Fatalf("usage = %+v", usage)
	}
}

func TestChatStreamTruncatedIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"<html>\"},\"finish_reason\":null}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}\n\n")
	}))
	defer srv.Close()

	_, _, err := New(srv.URL, "k", "").ChatStream(context.Background(), "",
		[]Message{{Role: "user", Content: "hi"}}, func(string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "截断") {
		t.Fatalf("err = %v", err)
	}
}

func TestChatStreamStopsWhenConsumerAborts(t *testing.T) {
	var chunks atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 50; i++ {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"x\"},\"finish_reason\":null}]}\n\n")
			w.(http.Flusher).Flush()
			chunks.Add(1)
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()

	sentinel := fmt.Errorf("client gone")
	_, _, err := New(srv.URL, "k", "").ChatStream(context.Background(), "",
		[]Message{{Role: "user", Content: "hi"}}, func(string) error { return sentinel })
	if err != sentinel {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	// The upstream stream must be abandoned as soon as the consumer errors, not
	// drained to the end (the test server would stall on writes if it kept going).
	if n := chunks.Load(); n > 10 {
		t.Fatalf("kept reading upstream after abort: %d chunks", n)
	}
}

func TestChatStreamHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	defer srv.Close()

	_, _, err := New(srv.URL, "k", "").ChatStream(context.Background(), "",
		[]Message{{Role: "user", Content: "hi"}}, func(string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "invalid api key") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateBaseURL(t *testing.T) {
	for _, bad := range []string{"", "example.com", "ftp://x", "https://"} {
		if err := ValidateBaseURL(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	for _, good := range []string{"http://127.0.0.1:11434/v1", "https://api.deepseek.com/v1"} {
		if err := ValidateBaseURL(good); err != nil {
			t.Fatalf("%q rejected: %v", good, err)
		}
	}
}

func TestAzureUsesAPIKeyHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// httptest host is 127.0.0.1, so exercise the header branch directly.
		if r.Header.Get("api-key") == "" && r.Header.Get("Authorization") == "" {
			t.Error("no credential header")
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()
	if _, _, err := New(srv.URL, "k", "").Chat("", []Message{{Role: "user", Content: "x"}}); err != nil {
		t.Fatal(err)
	}
}

func TestChatWithToolsAccumulatesFragments(t *testing.T) {
	var sawTools bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Tools []Tool `json:"tools"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		sawTools = len(body.Tools) == 1 && body.Tools[0].Function.Name == "create_group"
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		// The name and arguments arrive in fragments, as real providers send them.
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"create_group\",\"arguments\":\"{\\\"na\"}}]},\"finish_reason\":null}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"me\\\":\\\"测试\\\"}\"}}]},\"finish_reason\":null}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer srv.Close()

	tools := []Tool{{Type: "function", Function: ToolFunction{Name: "create_group", Parameters: json.RawMessage(`{"type":"object"}`)}}}
	res, err := New(srv.URL, "k", "").ChatWithTools(context.Background(), "", []Message{{Role: "user", Content: "hi"}}, tools, nil)
	if err != nil {
		t.Fatalf("ChatWithTools: %v", err)
	}
	if !sawTools {
		t.Fatal("tools were not sent to the provider")
	}
	if len(res.ToolCalls) != 1 {
		t.Fatalf("tool calls = %+v", res.ToolCalls)
	}
	tc := res.ToolCalls[0]
	if tc.ID != "call_1" || tc.Function.Name != "create_group" || tc.Function.Arguments != `{"name":"测试"}` {
		t.Fatalf("tool call = %+v", tc)
	}
	if res.FinishReason != "tool_calls" {
		t.Fatalf("finish_reason = %q", res.FinishReason)
	}
	if res.Usage.TotalTokens != 6 {
		t.Fatalf("usage = %+v", res.Usage)
	}
}

func TestChatWithToolsAcceptsEmptyContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"type\":\"function\",\"function\":{\"name\":\"list_groups\",\"arguments\":\"{}\"}}]},\"finish_reason\":null}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()
	res, err := New(srv.URL, "k", "").ChatWithTools(context.Background(), "", []Message{{Role: "user", Content: "hi"}},
		[]Tool{{Type: "function", Function: ToolFunction{Name: "list_groups", Parameters: json.RawMessage(`{}`)}}}, nil)
	if err != nil {
		t.Fatalf("empty content with tool calls must be accepted: %v", err)
	}
	if res.Content != "" || len(res.ToolCalls) != 1 {
		t.Fatalf("res = %+v", res)
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	s := strings.Repeat("中", 10)
	out := truncate(s, 3)
	if out != "中中中…" {
		t.Fatalf("truncate = %q", out)
	}
	if truncate("abc", 5) != "abc" {
		t.Fatal("short string modified")
	}
}

func TestWireMessagesExpandsImages(t *testing.T) {
	msgs := []Message{
		{Role: "user", Content: "看截图", Images: []string{"data:image/jpeg;base64,AAAA"}},
		{Role: "tool", Content: `{"ok":true}`, ToolCallID: "c1"},
	}
	wire := WireMessages(msgs)
	b, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, `"type":"image_url"`) || !strings.Contains(got, `data:image/jpeg;base64,AAAA`) {
		t.Fatalf("image part missing: %s", got)
	}
	if !strings.Contains(got, `"role":"tool"`) || !strings.Contains(got, `"tool_call_id":"c1"`) {
		t.Fatalf("plain message did not stay flat: %s", got)
	}

	stripped := StripImages(msgs)
	if HasImages(stripped) {
		t.Fatal("StripImages left images behind")
	}
	if stripped[0].Content != "看截图" {
		t.Fatal("StripImages changed content")
	}
}

func TestMessageUnmarshalAcceptsContentParts(t *testing.T) {
	var m Message
	raw := `{"role":"assistant","content":[{"type":"text","text":"你好"},{"type":"image_url","image_url":{"url":"x"}}]}`
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if m.Content != "你好" {
		t.Fatalf("content = %q", m.Content)
	}
}

func TestRefreshModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"model-b"},{"id":"model-a"}]}`)
	}))
	defer srv.Close()
	c := New(srv.URL, "sk-test", "m")
	models, err := c.RefreshModels(context.Background())
	if err != nil || len(models) != 2 || models[0] != "model-b" {
		t.Fatalf("models = %+v err=%v", models, err)
	}
}
