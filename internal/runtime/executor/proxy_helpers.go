package executor

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// httpClientCache caches HTTP clients by auth identity and normalized route identity to enable connection reuse.
var (
	httpClientCache      = make(map[string]*http.Client)
	httpClientCacheMutex sync.RWMutex
)

type proxyRouteIdentity struct {
	authID                 string
	source                 string
	routeMode              string
	routeKey               string
	cacheKey               string
	effectiveProxyURL      string
	canonicalProxyEndpoint string
	logTag                 string
	ipv6                   string
}

func resolveProxyRouteIdentity(cfg *config.Config, auth *cliproxyauth.Auth) proxyRouteIdentity {
	route := proxyRouteIdentity{
		source:    "inherit",
		routeMode: routeModeString(proxyutil.ModeInherit),
		logTag:    "direct-default",
	}
	if auth != nil {
		route.authID = strings.TrimSpace(auth.ID)
		route.ipv6 = codexAuthIPv6(auth)
		if proxyURL := strings.TrimSpace(auth.ProxyURL); proxyURL != "" {
			route.source = "explicit"
			route.effectiveProxyURL = proxyURL
		}
	}
	if route.effectiveProxyURL == "" && cfg != nil {
		if proxyURL := strings.TrimSpace(cfg.ProxyURL); proxyURL != "" {
			route.source = "default"
			route.effectiveProxyURL = proxyURL
		}
	}

	setting, errParse := proxyutil.Parse(route.effectiveProxyURL)
	if errParse != nil {
		route.routeMode = routeModeString(proxyutil.ModeInvalid)
		route.routeKey = "source=" + route.source + "|mode=" + route.routeMode + "|value=" + strings.ToLower(strings.TrimSpace(route.effectiveProxyURL))
		if route.ipv6 != "" {
			route.routeKey += "|ipv6=" + strings.ToLower(route.ipv6)
		}
		route.logTag = "proxy-invalid-" + route.source
		route.cacheKey = "auth=" + route.authID + "|route=" + route.routeKey
		return route
	}

	route.routeMode = routeModeString(setting.Mode)
	switch setting.Mode {
	case proxyutil.ModeProxy:
		route.canonicalProxyEndpoint = canonicalProxyEndpoint(setting)
		route.routeKey = "mode=" + route.routeMode + "|endpoint=" + route.canonicalProxyEndpoint
		if route.source == "explicit" {
			route.logTag = "proxy-explicit"
		} else {
			route.logTag = "proxy-default"
		}
	case proxyutil.ModeDirect:
		route.routeKey = "source=" + route.source + "|mode=" + route.routeMode
		if route.ipv6 != "" {
			route.logTag = "direct-ipv6-freebind"
		} else if route.source == "explicit" {
			route.logTag = "direct-explicit"
		} else {
			route.logTag = "direct-default"
		}
	default:
		route.routeKey = "source=inherit|mode=" + route.routeMode
		if route.ipv6 != "" {
			route.logTag = "direct-ipv6-freebind"
		} else {
			route.logTag = "direct-default"
		}
	}
	if route.routeKey == "" {
		route.routeKey = "source=" + route.source + "|mode=" + route.routeMode
	}
	if route.ipv6 != "" && setting.Mode != proxyutil.ModeProxy {
		route.routeKey += "|ipv6=" + strings.ToLower(route.ipv6)
	}
	route.cacheKey = "auth=" + route.authID + "|route=" + route.routeKey
	return route
}

func routeModeString(mode proxyutil.Mode) string {
	switch mode {
	case proxyutil.ModeDirect:
		return "direct"
	case proxyutil.ModeProxy:
		return "proxy"
	case proxyutil.ModeInvalid:
		return "invalid"
	default:
		return "inherit"
	}
}

func authMetadataString(auth *cliproxyauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if value, ok := auth.Metadata[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func codexAuthIPv6(auth *cliproxyauth.Auth) string {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return ""
	}
	raw := authMetadataString(auth, "ipv6")
	if raw == "" {
		return ""
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is6() {
		return ""
	}
	return addr.Unmap().String()
}

func canonicalProxyEndpoint(setting proxyutil.Setting) string {
	if setting.URL == nil {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(strings.ToLower(strings.TrimSpace(setting.URL.Scheme)))
	builder.WriteString("://")
	if setting.URL.User != nil {
		username := setting.URL.User.Username()
		if password, ok := setting.URL.User.Password(); ok {
			builder.WriteString(url.UserPassword(username, password).String())
		} else {
			builder.WriteString(url.User(username).String())
		}
		builder.WriteByte('@')
	}
	builder.WriteString(canonicalHostPort(setting.URL))
	return builder.String()
}

func canonicalHostPort(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(u.Host))
	}
	port := strings.TrimSpace(u.Port())
	if port == "" {
		port = defaultPortForScheme(u.Scheme)
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks5":
		return "1080"
	default:
		return ""
	}
}

func logProxyRouteDecision(route proxyRouteIdentity, transportSource string, cacheHit bool) {
	fields := log.Fields{
		"auth_id":          route.authID,
		"route_mode":       route.routeMode,
		"route_source":     route.source,
		"route_tag":        route.logTag,
		"transport_source": transportSource,
		"cache_hit":        cacheHit,
	}
	if route.ipv6 != "" {
		fields["ipv6"] = route.ipv6
	}
	log.WithFields(fields).Debug("executor network route selected")
}

// newProxyAwareHTTPClient creates an HTTP client with proper proxy configuration priority:
// 1. Use auth.ProxyURL if configured (highest priority)
// 2. Use cfg.ProxyURL if auth proxy is not configured
// 3. Use RoundTripper from context if neither are configured
//
// This function caches HTTP clients by auth identity and normalized route identity to enable TCP/TLS connection reuse.
//
// Parameters:
//   - ctx: The context containing optional RoundTripper
//   - cfg: The application configuration
//   - auth: The authentication information
//   - timeout: The client timeout (0 means no timeout)
//
// Returns:
//   - *http.Client: An HTTP client with configured proxy or transport
func newProxyAwareHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	route := resolveProxyRouteIdentity(cfg, auth)
	cacheable := route.routeMode == routeModeString(proxyutil.ModeDirect) || route.routeMode == routeModeString(proxyutil.ModeProxy) || (route.routeMode == routeModeString(proxyutil.ModeInherit) && route.ipv6 != "")
	if cacheable {
		httpClientCacheMutex.RLock()
		if cachedClient, ok := httpClientCache[route.cacheKey]; ok {
			httpClientCacheMutex.RUnlock()
			logProxyRouteDecision(route, "cache", true)
			if timeout > 0 {
				return &http.Client{Transport: cachedClient.Transport, Timeout: timeout}
			}
			return cachedClient
		}
		httpClientCacheMutex.RUnlock()
	}

	httpClient := &http.Client{}
	if timeout > 0 {
		httpClient.Timeout = timeout
	}

	storeCached := func(source string) *http.Client {
		if cacheable {
			httpClientCacheMutex.Lock()
			httpClientCache[route.cacheKey] = httpClient
			httpClientCacheMutex.Unlock()
		}
		logProxyRouteDecision(route, source, false)
		return httpClient
	}

	switch route.routeMode {
	case routeModeString(proxyutil.ModeProxy):
		transport := buildProxyTransport(route.effectiveProxyURL)
		if transport != nil {
			httpClient.Transport = transport
			return storeCached("proxy")
		}
		logProxyRouteDecision(route, "fallback", false)
		log.Debugf("failed to setup proxy from route %s, falling back to context transport", route.logTag)
	case routeModeString(proxyutil.ModeDirect), routeModeString(proxyutil.ModeInherit):
		if route.ipv6 != "" {
			transport, errIPv6 := util.NewIPv6Transport(route.ipv6)
			if errIPv6 == nil {
				httpClient.Transport = transport
				return storeCached("ipv6")
			}
			log.WithError(errIPv6).Warnf("executor network route %s: failed to configure IPv6 transport", route.logTag)
		}
		if route.routeMode == routeModeString(proxyutil.ModeDirect) {
			httpClient.Transport = proxyutil.NewDirectTransport()
			return storeCached("direct")
		}
	}

	if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
		httpClient.Transport = rt
		logProxyRouteDecision(route, "context", false)
		return httpClient
	}

	logProxyRouteDecision(route, "default", false)
	return httpClient
}

// buildProxyTransport creates an HTTP transport configured for the given proxy URL.
// It supports SOCKS5, HTTP, and HTTPS proxy protocols.
//
// Parameters:
//   - proxyURL: The proxy URL string (e.g., "socks5://user:pass@host:port", "http://host:port")
//
// Returns:
//   - *http.Transport: A configured transport, or nil if the proxy URL is invalid
func buildProxyTransport(proxyURL string) *http.Transport {
	transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		log.Errorf("%v", errBuild)
		return nil
	}
	return transport
}
