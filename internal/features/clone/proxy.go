package clone

// Reverse-proxy helpers. A proxy landing page does not store an HTML snapshot;
// it forwards the upstream site's live responses through the portal, so a
// client-rendered app keeps working: its bundle, lazy chunks, API calls and
// session cookies are all served from the portal's own origin under
// <prefix>/px/. Only same-origin references are rewritten; external CDNs are
// left absolute and load directly (the recipient's browser talks to them, not
// to the portal).
//
// Two pieces make a path-prefixed proxy work for an SPA:
//   - ProxyRewriteHTML/ProxyRewriteCSS rewrite absolute paths in the initial
//     document and stylesheets (relative paths already resolve inside the
//     prefix because they are relative to the proxied document URL).
//   - ProxyShim installs runtime patches for fetch/XHR/WebSocket/EventSource
//     and a MutationObserver, so dynamically created elements and API calls
//     that use absolute paths ("/api/login") are routed back through the
//     prefix instead of hitting the portal root.
//
// Known limitations (documented, not bugs): navigations performed by direct
// location assignment, service workers, and WebSocket upgrades are not proxied.

import (
	"encoding/json"
	"net/url"
	"strings"
)

// ProxyURL maps one upstream URL onto the portal prefix. It returns false when
// the value is not a same-origin URL (external CDN, data:, javascript:, etc.).
// prefix must end with "/" and must not include the trailing "px/" segment;
// the caller passes the full proxy root, e.g. "/l/ab12/px/".
func ProxyURL(raw string, base *url.URL, prefix string) (string, bool) {
	if base == nil || prefix == "" {
		return "", false
	}
	t := strings.TrimSpace(raw)
	if skipScheme(t) {
		return "", false
	}
	// Protocol-relative URL: same origin only when the host matches.
	if strings.HasPrefix(t, "//") {
		u, err := url.Parse(t)
		if err != nil || !strings.EqualFold(u.Host, base.Host) {
			return "", false
		}
		return prefix + strings.TrimPrefix(u.RequestURI(), "/"), true
	}
	// Root-absolute path: always ours after rewriting.
	if strings.HasPrefix(t, "/") {
		return prefix + strings.TrimPrefix(t, "/"), true
	}
	u, err := url.Parse(t)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return "", false
	}
	if !strings.EqualFold(u.Host, base.Host) || !strings.EqualFold(u.Scheme, base.Scheme) {
		return "", false
	}
	return prefix + strings.TrimPrefix(u.RequestURI(), "/"), true
}

// ProxyRewriteHTML rewrites a live upstream document for serving under prefix.
// It strips a CSP meta and SRI attributes (they would block our injected shim
// and the rewritten bundles) and injects ProxyShim before any app script.
func ProxyRewriteHTML(doc []byte, pageURL *url.URL, prefix string) []byte {
	s := string(doc)
	base := pageBase(pageURL, doc)
	s = cspMetaRe.ReplaceAllString(s, "")
	s = integrityAttrRe.ReplaceAllString(s, "")

	s = linkTagRe.ReplaceAllStringFunc(s, func(tag string) string {
		return replaceTagAttr(tag, "href", func(v string) (string, bool) {
			return ProxyURL(v, base, prefix)
		})
	})
	s = anchorTagRe.ReplaceAllStringFunc(s, func(tag string) string {
		return replaceTagAttr(tag, "href", func(v string) (string, bool) {
			return ProxyURL(v, base, prefix)
		})
	})
	s = genericAttr.ReplaceAllStringFunc(s, func(m string) string {
		sub := genericAttr.FindStringSubmatch(m)
		if len(sub) < 5 {
			return m
		}
		name := strings.ToLower(sub[1])
		v := sub[2]
		if v == "" {
			v = sub[3]
		}
		if v == "" {
			v = sub[4]
		}
		out, ok := ProxyURL(v, base, prefix)
		if !ok {
			return m
		}
		return name + "=" + quoted(out)
	})
	s = srcsetRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := srcsetRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		v := sub[1]
		if v == "" {
			v = sub[2]
		}
		return "srcset=" + quoted(proxySrcset(v, base, prefix))
	})
	s = styleRe.ReplaceAllStringFunc(s, func(block string) string {
		m := styleRe.FindStringSubmatch(block)
		if len(m) < 4 {
			return block
		}
		return m[1] + string(ProxyRewriteCSS([]byte(m[2]), base, prefix)) + m[3]
	})
	s = styleAttr.ReplaceAllStringFunc(s, func(m string) string {
		sub := styleAttr.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		v := sub[1]
		if v == "" {
			v = sub[2]
		}
		return `style="` + attrQuote(string(ProxyRewriteCSS([]byte(v), base, prefix))) + `"`
	})
	// A foreign <base href> would send relative URLs to another host; point it
	// at our proxy root instead so relative resolution stays inside the clone.
	s = baseTagRe.ReplaceAllString(s, `<base href="`+attrQuote(prefix)+`">`)
	return []byte(injectProxyShim(s, prefix))
}

// ProxyRewriteCSS rewrites url(...) and @import references in a live
// stylesheet. Relative url() values resolve against the stylesheet's proxied
// URL already, so only root-absolute / same-origin values need rewriting.
func ProxyRewriteCSS(css []byte, base *url.URL, prefix string) []byte {
	body := string(css)
	body = cssURLRe.ReplaceAllStringFunc(body, func(m string) string {
		sub := cssURLRe.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		out, ok := ProxyURL(strings.TrimSpace(sub[2]), base, prefix)
		if !ok {
			return m
		}
		return `url("` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `(`, `\(`, `)`, `\)`).Replace(out) + `")`
	})
	return []byte(body)
}

// proxySrcset rewrites each srcset candidate through ProxyURL.
func proxySrcset(v string, base *url.URL, prefix string) string {
	parts := strings.Split(v, ",")
	for i, p := range parts {
		fields := strings.Fields(strings.TrimSpace(p))
		if len(fields) == 0 {
			continue
		}
		if out, ok := ProxyURL(fields[0], base, prefix); ok {
			fields[0] = out
		}
		parts[i] = strings.Join(fields, " ")
	}
	return strings.Join(parts, ", ")
}

// attrQuote escapes a value for a double-quoted HTML attribute. The CSS
// rewriter already operates on attribute text, so only & and " need escaping.
func attrQuote(v string) string {
	return strings.NewReplacer("&", "&amp;", `"`, "&quot;").Replace(v)
}

func injectProxyShim(s, prefix string) string {
	block := `<script data-hp-proxy="1">` + ProxyShimJS(prefix) + `</script>`
	return injectAfterHead(s, block)
}

// ProxyShimJS returns the runtime adapter for a proxy landing page. It routes
// absolute-path requests and DOM references back through prefix so an SPA does
// not talk to the portal root, and it refuses to register service workers
// (they would bypass the prefix forever).
func ProxyShimJS(prefix string) string {
	p, _ := json.Marshal(prefix)
	return `(function(){if(window.__HP_PROXY__)return;window.__HP_PROXY__=1;
var P=` + string(p) + `;if(P&&P.charAt(P.length-1)!=='/')P+='/';
var OWN=['/l/','/p/','/b/','/t/','/r/','/u/','/__admin','/vendor/','/favicon.ico'];
var own=function(s){for(var i=0;i<OWN.length;i++){if(s.indexOf(OWN[i])===0)return true}return false};
var map=function(u){
  try{
    if(typeof u!=='string'||!u)return u;
    if(/^(?:javascript|data|blob|mailto|tel|about|chrome-extension):/i.test(u))return u;
    if(u.charAt(0)==='#')return u;
    if(u.charAt(0)==='/'&&u.charAt(1)!=='/'){
      if(u.indexOf(P)===0||own(u))return u;
      return P+u.slice(1);
    }
    var a=new URL(u,location.href);
    if(a.origin===location.origin&&a.pathname.indexOf(P)!==0&&!own(a.pathname)){
      return P+a.pathname.replace(/^\/+/,'')+(a.search||'')+(a.hash||'');
    }
  }catch(e){}
  return u;
};
var fixAttr=function(el,names){
  for(var i=0;i<names.length;i++){
    var n=names[i],v=el.getAttribute&&el.getAttribute(n);
    if(!v)continue;
    var m=map(v);
    if(m!==v){try{el.setAttribute(n,m)}catch(e){}}
  }
};
var fixEl=function(el){
  try{
    if(!el||el.nodeType!==1)return;
    fixAttr(el,['src','href','action','poster','data-src','formaction']);
    if(el.querySelectorAll){
      var all=el.querySelectorAll('[src],[href],[action],[poster],[data-src],[formaction]');
      for(var i=0;i<all.length;i++)fixAttr(all[i],['src','href','action','poster','data-src','formaction']);
    }
  }catch(e){}
};
try{
  new MutationObserver(function(ms){
    for(var i=0;i<ms.length;i++){
      var m=ms[i];
      if(m.type==='attributes'){fixEl(m.target);continue}
      for(var j=0;j<m.addedNodes.length;j++)fixEl(m.addedNodes[j]);
    }
  }).observe(document.documentElement,{childList:true,subtree:true,attributes:true,
    attributeFilter:['src','href','action','poster','data-src','formaction']});
}catch(e){}
var of=window.fetch;
if(of){window.fetch=function(input,init){
  try{
    if(typeof input==='string'||input instanceof URL){var u=map(String(input));if(u!==String(input))input=u}
    else if(input&&input.url){var v=map(input.url);if(v!==input.url)input=new Request(v,input)}
  }catch(e){}
  return of.apply(this,arguments)};
}
var XO=window.XMLHttpRequest;
if(XO&&XO.prototype.open){var xo=XO.prototype.open;XO.prototype.open=function(m,u){
  try{arguments[1]=map(String(u))}catch(e){}
  return xo.apply(this,arguments)};}
var ES=window.EventSource;
if(ES){window.EventSource=function(u,o){
  var v=map(String(u)).replace(/^https:/i,'wss:').replace(/^http:/i,'ws:');
  return o===undefined?new ES(v):new ES(v,o)};
  window.EventSource.prototype=ES.prototype;}
var WS=window.WebSocket;
if(WS){window.WebSocket=function(u,o){
  var v=map(String(u)).replace(/^https:/i,'wss:').replace(/^http:/i,'ws:');
  return o===undefined?new WS(v):new WS(v,o)};
  window.WebSocket.prototype=WS.prototype;}
if(navigator.sendBeacon){var bc=navigator.sendBeacon.bind(navigator);
  navigator.sendBeacon=function(u,d){try{u=map(String(u))}catch(e){}return bc(u,d)};}
if(window.open){var wo=window.open;
  window.open=function(u){try{if(u)arguments[0]=map(String(u))}catch(e){}return wo.apply(this,arguments)};}
try{var ps=history.pushState,rs=history.replaceState;
  history.pushState=function(s,t,u){if(u)arguments[2]=map(String(u));return ps.apply(this,arguments)};
  history.replaceState=function(s,t,u){if(u)arguments[2]=map(String(u));return rs.apply(this,arguments)};
}catch(e){}
try{if(navigator.serviceWorker){
  navigator.serviceWorker.register=function(){return Promise.reject(new Error('service worker disabled on proxy page'))};
}}catch(e){}
})();`
}
