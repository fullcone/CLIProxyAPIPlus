package executor

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

// httpClientCache caches HTTP clients by proxy URL to enable connection reuse
var (
	httpClientCache      = make(map[string]*http.Client)
	httpClientCacheMutex sync.RWMutex
)

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
	// Check for IPv6 source address binding (Codex accounts with eBPF SNAT)
	var ipv6Addr string
	if auth != nil && auth.Metadata != nil {
		if v, ok := auth.Metadata["ipv6"].(string); ok {
			ipv6Addr = strings.TrimSpace(v)
		}
	}

	if ipv6Addr != "" {
		// Build cache key including IPv6 to isolate connection pools
		var authID string
		if auth != nil {
			authID = auth.ID
		}
		cacheKey := "ipv6|" + ipv6Addr + "|" + authID

		// Check cache first
		httpClientCacheMutex.RLock()
		if cachedClient, ok := httpClientCache[cacheKey]; ok {
			httpClientCacheMutex.RUnlock()
			if timeout > 0 {
				return &http.Client{
					Transport: cachedClient.Transport,
					Timeout:   timeout,
				}
			}
			return cachedClient
		}
		httpClientCacheMutex.RUnlock()

		// Create IPv6-bound transport with IP_FREEBIND
		srcIP := net.ParseIP(ipv6Addr)
		dialer := &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: srcIP},
			Control: func(network, address string, c syscall.RawConn) error {
				var opErr error
				if err := c.Control(func(fd uintptr) {
					// IPV6_FREEBIND = 78 on Linux (not exported by syscall package)
					opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, 78, 1)
				}); err != nil {
					return err
				}
				return opErr
			},
		}
		transport := &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialer.DialContext(dialCtx, "tcp6", addr)
				if err != nil {
					log.Warnf("IPv6 dial failed: src=%s dst=%s err=%v", ipv6Addr, addr, err)
					return nil, err
				}
				log.Debugf("IPv6 dial success: src=%s dst=%s local=%s", ipv6Addr, addr, conn.LocalAddr())
				return conn, nil
			},
		}

		httpClient := &http.Client{Transport: transport}
		if timeout > 0 {
			httpClient.Timeout = timeout
		}

		httpClientCacheMutex.Lock()
		httpClientCache[cacheKey] = httpClient
		httpClientCacheMutex.Unlock()
		return httpClient
	}

	// Priority 1: Use auth.ProxyURL if configured
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}

	// Priority 2: Use cfg.ProxyURL if auth proxy is not configured
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	// Build cache key from proxy URL + auth ID to isolate connection pools per auth
	var authID string
	if auth != nil {
		authID = auth.ID
	}
	cacheKey := proxyURL + "|" + authID

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

	// Priority 3: Use RoundTripper from context (typically from RoundTripperFor)
	if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
		httpClient.Transport = rt
	}

	// Cache the client for no-proxy case
	if proxyURL == "" {
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
	if proxyURL == "" {
		return nil
	}

	parsedURL, errParse := url.Parse(proxyURL)
	if errParse != nil {
		log.Errorf("parse proxy URL failed: %v", errParse)
		return nil
	}

	var transport *http.Transport

	// Handle different proxy schemes
	if parsedURL.Scheme == "socks5" {
		// Configure SOCKS5 proxy with optional authentication
		var proxyAuth *proxy.Auth
		if parsedURL.User != nil {
			username := parsedURL.User.Username()
			password, _ := parsedURL.User.Password()
			proxyAuth = &proxy.Auth{User: username, Password: password}
		}
		dialer, errSOCKS5 := proxy.SOCKS5("tcp", parsedURL.Host, proxyAuth, proxy.Direct)
		if errSOCKS5 != nil {
			log.Errorf("create SOCKS5 dialer failed: %v", errSOCKS5)
			return nil
		}
		// Set up a custom transport using the SOCKS5 dialer
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		}
	} else if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
		// Configure HTTP or HTTPS proxy
		transport = &http.Transport{Proxy: http.ProxyURL(parsedURL)}
	} else {
		log.Errorf("unsupported proxy scheme: %s", parsedURL.Scheme)
		return nil
	}

	return transport
}
