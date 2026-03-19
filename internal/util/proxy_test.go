package util

import (
	"net/http"
	"testing"

	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func TestSetProxyDirectPreservesExistingTransport(t *testing.T) {
	t.Parallel()

	existing := &http.Transport{}
	client := &http.Client{Transport: existing}

	SetProxy(&sdkconfig.SDKConfig{ProxyURL: "direct"}, client)

	if client.Transport != existing {
		t.Fatal("expected direct proxy mode to preserve existing transport")
	}
}
