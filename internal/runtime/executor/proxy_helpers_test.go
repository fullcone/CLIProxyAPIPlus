package executor

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func resetHTTPClientCacheForTest() {
	httpClientCacheMutex.Lock()
	defer httpClientCacheMutex.Unlock()
	httpClientCache = make(map[string]*http.Client)
}

func TestNewProxyAwareHTTPClientDirectBypassesGlobalProxy(t *testing.T) {
	resetHTTPClientCacheForTest()

	client := newProxyAwareHTTPClient(
		context.Background(),
		&config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"}},
		&cliproxyauth.Auth{ID: "auth-direct", ProxyURL: "direct"},
		0,
	)

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("expected direct transport to disable proxy function")
	}
}

func TestResolveProxyRouteIdentity_CacheKeyIncludesCodexIPv6(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	routeA := resolveProxyRouteIdentity(cfg, &cliproxyauth.Auth{ID: "auth-1", Provider: "codex", Metadata: map[string]any{"ipv6": "2001:db8::1"}})
	routeB := resolveProxyRouteIdentity(cfg, &cliproxyauth.Auth{ID: "auth-1", Provider: "codex", Metadata: map[string]any{"ipv6": "2001:db8::2"}})

	if routeA.cacheKey == routeB.cacheKey {
		t.Fatalf("expected different cache keys for different IPv6 bindings, got %q", routeA.cacheKey)
	}
	if routeA.logTag != "direct-ipv6-freebind" || routeB.logTag != "direct-ipv6-freebind" {
		t.Fatalf("unexpected log tags: %q / %q", routeA.logTag, routeB.logTag)
	}
}

func TestResolveProxyRouteIdentity_InvalidProxyStillSeparatesCodexIPv6(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	routeA := resolveProxyRouteIdentity(cfg, &cliproxyauth.Auth{ID: "auth-1", Provider: "codex", ProxyURL: "bad-proxy", Metadata: map[string]any{"ipv6": "2001:db8::1"}})
	routeB := resolveProxyRouteIdentity(cfg, &cliproxyauth.Auth{ID: "auth-1", Provider: "codex", ProxyURL: "bad-proxy", Metadata: map[string]any{"ipv6": "2001:db8::2"}})

	if routeA.cacheKey == routeB.cacheKey {
		t.Fatalf("expected invalid proxy cache keys to differ across IPv6 bindings, got %q", routeA.cacheKey)
	}
	if routeA.logTag != "proxy-invalid-explicit" || routeB.logTag != "proxy-invalid-explicit" {
		t.Fatalf("unexpected invalid proxy log tags: %q / %q", routeA.logTag, routeB.logTag)
	}
}

func TestResolveProxyRouteIdentity_NormalizesEquivalentProxyURLs(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	left := resolveProxyRouteIdentity(cfg, &cliproxyauth.Auth{ID: "auth-1", ProxyURL: "http://Proxy.EXAMPLE.com/"})
	right := resolveProxyRouteIdentity(cfg, &cliproxyauth.Auth{ID: "auth-1", ProxyURL: "http://proxy.example.com:80"})

	if left.routeKey != right.routeKey {
		t.Fatalf("routeKey mismatch: %q != %q", left.routeKey, right.routeKey)
	}
	if left.logTag != "proxy-explicit" || right.logTag != "proxy-explicit" {
		t.Fatalf("unexpected log tags: %q / %q", left.logTag, right.logTag)
	}
}

func TestResolveProxyRouteIdentity_MergesDefaultAndExplicitEquivalentProxyRoute(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://Proxy.EXAMPLE.com/"}}
	defaultRoute := resolveProxyRouteIdentity(cfg, &cliproxyauth.Auth{ID: "auth-1"})
	explicitRoute := resolveProxyRouteIdentity(cfg, &cliproxyauth.Auth{ID: "auth-1", ProxyURL: "http://proxy.example.com:80"})

	if defaultRoute.routeKey != explicitRoute.routeKey {
		t.Fatalf("routeKey mismatch: %q != %q", defaultRoute.routeKey, explicitRoute.routeKey)
	}
	if defaultRoute.logTag != "proxy-default" {
		t.Fatalf("default log tag = %q, want %q", defaultRoute.logTag, "proxy-default")
	}
	if explicitRoute.logTag != "proxy-explicit" {
		t.Fatalf("explicit log tag = %q, want %q", explicitRoute.logTag, "proxy-explicit")
	}
}

func TestResolveProxyRouteIdentity_DistinguishesInheritFromExplicitDirect(t *testing.T) {
	t.Parallel()

	inheritRoute := resolveProxyRouteIdentity(&config.Config{}, &cliproxyauth.Auth{ID: "auth-1"})
	directRoute := resolveProxyRouteIdentity(&config.Config{}, &cliproxyauth.Auth{ID: "auth-1", ProxyURL: "none"})

	if inheritRoute.routeKey == directRoute.routeKey {
		t.Fatalf("expected inherit and explicit direct routes to differ, got %q", inheritRoute.routeKey)
	}
	if inheritRoute.logTag != "direct-default" {
		t.Fatalf("inherit log tag = %q, want %q", inheritRoute.logTag, "direct-default")
	}
	if directRoute.logTag != "direct-explicit" {
		t.Fatalf("direct log tag = %q, want %q", directRoute.logTag, "direct-explicit")
	}
}

func TestNewProxyAwareHTTPClient_CacheSeparatesAuthID(t *testing.T) {
	resetHTTPClientCacheForTest()

	cfg := &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"}}
	clientA := newProxyAwareHTTPClient(context.Background(), cfg, &cliproxyauth.Auth{ID: "auth-a"}, 0)
	clientB := newProxyAwareHTTPClient(context.Background(), cfg, &cliproxyauth.Auth{ID: "auth-b"}, 0)

	transportA, okA := clientA.Transport.(*http.Transport)
	transportB, okB := clientB.Transport.(*http.Transport)
	if !okA || !okB {
		t.Fatalf("unexpected transport types: %T / %T", clientA.Transport, clientB.Transport)
	}
	if transportA == transportB {
		t.Fatal("expected different auth IDs to use different cached transports")
	}
}
