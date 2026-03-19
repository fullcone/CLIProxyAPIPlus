package executor

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func TestNewProxyAwareHTTPClientDirectBypassesGlobalProxy(t *testing.T) {
	t.Parallel()

	client := newProxyAwareHTTPClient(
		context.Background(),
		&config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"}},
		&cliproxyauth.Auth{ProxyURL: "direct"},
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

func TestResolveNetworkRouteDecisionDirectStillUsesIPv6(t *testing.T) {
	t.Parallel()

	decision := resolveNetworkRouteDecision(
		&config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "direct"}},
		&cliproxyauth.Auth{
			ID: "auth-1",
			Metadata: map[string]any{
				"ipv6": "2001:db8::10",
			},
		},
	)

	if decision.proxyOrigin != codexNetOriginDefault {
		t.Fatalf("proxy origin = %s, want %s", decision.proxyOrigin, codexNetOriginDefault)
	}
	if decision.routeMode != codexNetModeDirectIPv6Freebind {
		t.Fatalf("route mode = %s, want %s", decision.routeMode, codexNetModeDirectIPv6Freebind)
	}
}
