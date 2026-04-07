package helps

import (
	"context"
	"fmt"
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

// NormalizeRouteKey builds a stable cache key from proxy, auth, and IPv6 settings.
// It is exported so that other packages (e.g. codex_executor) can derive
// the same key for their own caches.
func NormalizeRouteKey(proxyURL string, authID string, ipv6 string) string {
	mode := "inherit"
	trimmed := strings.TrimSpace(proxyURL)
	if trimmed != "" {
		setting, err := proxyutil.Parse(trimmed)
		if err != nil {
			// Fallback: use raw string when parsing fails.
			mode = trimmed
		} else {
			switch setting.Mode {
			case proxyutil.ModeDirect:
				mode = "direct"
			case proxyutil.ModeProxy:
				if setting.URL != nil {
					mode = strings.ToLower(setting.URL.Scheme) + "://" + strings.ToLower(setting.URL.Host)
				} else {
					mode = trimmed
				}
			case proxyutil.ModeInherit:
				mode = "inherit"
			default:
				mode = trimmed
			}
		}
	}
	return fmt.Sprintf("route:%s|auth:%s|ipv6:%s", mode, authID, ipv6)
}

// NewProxyAwareHTTPClient creates an HTTP client with proper proxy configuration priority:
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
func NewProxyAwareHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	// Priority 1: Use auth.ProxyURL if configured
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}

	// Priority 2: Use cfg.ProxyURL if auth proxy is not configured
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	// Build normalized cache key incorporating auth identity and IPv6 setting.
	var authID, ipv6 string
	if auth != nil {
		authID = auth.ID
		if auth.Metadata != nil {
			if v, ok := auth.Metadata["ipv6"].(string); ok {
				ipv6 = v
			}
		}
	}
	cacheKey := NormalizeRouteKey(proxyURL, authID, ipv6)

	// Codex network diagnostic debug log.
	if auth != nil && auth.Provider == "codex" {
		netMode := "direct-default"
		if proxyURL != "" {
			netMode = "proxy-explicit"
			setting, err := proxyutil.Parse(proxyURL)
			if err == nil && setting.Mode == proxyutil.ModeDirect {
				netMode = "proxy-default"
			}
		} else if ipv6 != "" {
			netMode = "direct-ipv6-freebind"
		}
		log.Debugf("codex-net-mode=%s codex-net-auth=%s", netMode, authID)
	}

	// If we have a proxy URL configured, try cache first to reuse TCP/TLS connections.
	if proxyURL != "" {
		httpClientCacheMutex.RLock()
		if cachedClient, ok := httpClientCache[cacheKey]; ok {
			httpClientCacheMutex.RUnlock()
			if timeout > 0 {
				return &http.Client{Transport: cachedClient.Transport, Timeout: timeout}
			}
			return cachedClient
		}
		httpClientCacheMutex.RUnlock()
	}

	// Create new client
	httpClient := &http.Client{}
	if timeout > 0 {
		httpClient.Timeout = timeout
	}

	// If we have a proxy URL configured, set up the transport
	if proxyURL != "" {
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

	// Priority 2.5: If no proxy or direct/none, use IPv6 transport when available.
	if ipv6 != "" && isDirectOrNoneProxy(proxyURL) {
		transport := util.NewIPv6Transport(ipv6)
		httpClient.Transport = transport
		httpClientCacheMutex.Lock()
		httpClientCache[cacheKey] = httpClient
		httpClientCacheMutex.Unlock()
		return httpClient
	}

	// Priority 3: Use RoundTripper from context (typically from RoundTripperFor)
	if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
		httpClient.Transport = rt
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

// isDirectOrNoneProxy returns true when the proxy URL indicates no proxy should be used.
func isDirectOrNoneProxy(proxyURL string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(proxyURL))
	if trimmed == "" || trimmed == "direct" || trimmed == "none" {
		return true
	}
	setting, err := proxyutil.Parse(proxyURL)
	if err != nil {
		return false
	}
	return setting.Mode == proxyutil.ModeDirect || setting.Mode == proxyutil.ModeInherit
}
