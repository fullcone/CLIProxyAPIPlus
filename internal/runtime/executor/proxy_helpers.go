package executor

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// httpClientCache caches HTTP clients by proxy URL to enable connection reuse
var (
	httpClientCache      = make(map[string]*http.Client)
	httpClientCacheMutex sync.RWMutex
)

const (
	codexNetOriginInherit  = "proxy-inherit"
	codexNetOriginExplicit = "proxy-explicit"
	codexNetOriginDefault  = "proxy-default"

	codexNetModeDirectDefault      = "direct-default"
	codexNetModeDirectIPv6Freebind = "direct-ipv6-freebind"
	codexNetModeProxyExplicit      = "proxy-explicit"
	codexNetModeProxyDefault       = "proxy-default"
	codexNetModeProxyInvalid       = "proxy-invalid-fallback"
)

type networkRouteDecision struct {
	rawProxyURL string
	proxyOrigin string
	proxyMode   proxyutil.Mode
	routeMode   string
	authID      string
	ipv6Addr    string
}

func resolveNetworkRouteDecision(cfg *config.Config, auth *cliproxyauth.Auth) networkRouteDecision {
	decision := networkRouteDecision{
		proxyOrigin: codexNetOriginInherit,
		proxyMode:   proxyutil.ModeInherit,
		routeMode:   codexNetModeDirectDefault,
	}
	if auth != nil {
		decision.authID = strings.TrimSpace(auth.ID)
		if auth.Metadata != nil {
			if v, ok := auth.Metadata["ipv6"].(string); ok {
				decision.ipv6Addr = strings.TrimSpace(v)
			}
		}
		if raw := strings.TrimSpace(auth.ProxyURL); raw != "" {
			decision.rawProxyURL = raw
			decision.proxyOrigin = codexNetOriginExplicit
		}
	}
	if decision.rawProxyURL == "" && cfg != nil {
		if raw := strings.TrimSpace(cfg.ProxyURL); raw != "" {
			decision.rawProxyURL = raw
			decision.proxyOrigin = codexNetOriginDefault
		}
	}
	if decision.rawProxyURL != "" {
		setting, errParse := proxyutil.Parse(decision.rawProxyURL)
		if errParse != nil {
			decision.proxyMode = proxyutil.ModeInvalid
			decision.routeMode = codexNetModeProxyInvalid
			return decision
		}
		decision.proxyMode = setting.Mode
	}
	switch decision.proxyMode {
	case proxyutil.ModeProxy:
		if decision.proxyOrigin == codexNetOriginExplicit {
			decision.routeMode = codexNetModeProxyExplicit
		} else {
			decision.routeMode = codexNetModeProxyDefault
		}
	case proxyutil.ModeDirect, proxyutil.ModeInherit:
		if decision.ipv6Addr != "" {
			decision.routeMode = codexNetModeDirectIPv6Freebind
		} else {
			decision.routeMode = codexNetModeDirectDefault
		}
	default:
		decision.routeMode = codexNetModeProxyInvalid
	}
	return decision
}

func logCodexNetworkDecision(scope, target string, decision networkRouteDecision) {
	log.Debugf(
		"codex-net-scope=%s codex-net-mode=%s codex-net-origin=%s auth=%s target=%s ipv6=%s raw_proxy=%q",
		strings.TrimSpace(scope),
		decision.routeMode,
		decision.proxyOrigin,
		decision.authID,
		strings.TrimSpace(target),
		decision.ipv6Addr,
		decision.rawProxyURL,
	)
}

// newProxyAwareHTTPClient creates an HTTP client with proper proxy configuration priority:
// 1. Use auth.ProxyURL if configured (highest priority)
// 2. Use cfg.ProxyURL if auth proxy is not configured
// 3. Use RoundTripper from context if neither are configured
//
// This function caches HTTP clients by proxy URL to enable TCP/TLS connection reuse.
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
	decision := resolveNetworkRouteDecision(cfg, auth)
	authID := decision.authID
	ipv6Addr := decision.ipv6Addr
	proxyURL := decision.rawProxyURL

	// Build cache key from proxy URL and auth ID so different auths do not
	// accidentally share the same connection pool when routed through one proxy.
	cacheKey := proxyURL + "|" + authID
	if ipv6Addr != "" {
		cacheKey += "|ipv6:" + ipv6Addr
	}

	// Check cache first
	httpClientCacheMutex.RLock()
	if cachedClient, ok := httpClientCache[cacheKey]; ok {
		httpClientCacheMutex.RUnlock()
		// Return a wrapper with the requested timeout but shared transport
		if timeout > 0 {
			return &http.Client{
				Transport: cachedClient.Transport,
				Timeout:   timeout,
			}
		}
		return cachedClient
	}
	httpClientCacheMutex.RUnlock()

	// Create new client
	httpClient := &http.Client{}
	if timeout > 0 {
		httpClient.Timeout = timeout
	}

	if decision.proxyMode == proxyutil.ModeProxy {
		transport := buildProxyTransport(proxyURL)
		if transport != nil {
			httpClient.Transport = transport
			// Cache the client
			httpClientCacheMutex.Lock()
			httpClientCache[cacheKey] = httpClient
			httpClientCacheMutex.Unlock()
			return httpClient
		}
		// If proxy setup failed, log and fall through to context RoundTripper
		log.Debugf("failed to setup proxy from URL: %s, falling back to context transport", proxyURL)
	}
	if decision.routeMode == codexNetModeDirectIPv6Freebind {
		transport, errIPv6 := util.NewIPv6Transport(ipv6Addr)
		if errIPv6 == nil {
			httpClient.Transport = transport
			httpClientCacheMutex.Lock()
			httpClientCache[cacheKey] = httpClient
			httpClientCacheMutex.Unlock()
			return httpClient
		}
		log.Warnf("failed to setup ipv6 transport for %s: %v", ipv6Addr, errIPv6)
	}
	if decision.proxyMode == proxyutil.ModeDirect {
		httpClient.Transport = proxyutil.NewDirectTransport()
		httpClientCacheMutex.Lock()
		httpClientCache[cacheKey] = httpClient
		httpClientCacheMutex.Unlock()
		return httpClient
	}

	// Priority 3: Use RoundTripper from context (typically from RoundTripperFor)
	if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
		httpClient.Transport = rt
	}

	// Cache the client for no-proxy case
	if decision.proxyMode != proxyutil.ModeProxy {
		httpClientCacheMutex.Lock()
		httpClientCache[cacheKey] = httpClient
		httpClientCacheMutex.Unlock()
	}

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
