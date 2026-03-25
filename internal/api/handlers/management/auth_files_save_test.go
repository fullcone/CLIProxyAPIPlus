package management

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestSaveTokenRecord_RegistersAuthManagerImmediately(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	record := &coreauth.Auth{
		ID:       "codex-user@example.com-plus.json",
		Provider: "codex",
		FileName: "codex-user@example.com-plus.json",
		Metadata: map[string]any{
			"type":          "codex",
			"email":         "user@example.com",
			"access_token":  "access-token",
			"refresh_token": "refresh-token",
			"last_refresh":  "2026-03-13T00:00:00Z",
		},
	}

	savedPath, err := h.saveTokenRecord(context.Background(), record)
	if err != nil {
		t.Fatalf("saveTokenRecord error: %v", err)
	}
	if _, errStat := os.Stat(savedPath); errStat != nil {
		t.Fatalf("expected auth file to exist at %s: %v", savedPath, errStat)
	}

	authID := h.authIDForPath(savedPath)
	saved, ok := manager.GetByID(authID)
	if !ok {
		t.Fatalf("expected auth manager to contain saved auth %q", authID)
	}
	if saved.Provider != "codex" {
		t.Fatalf("provider = %q, want %q", saved.Provider, "codex")
	}
	if got := authEmail(saved); got != "user@example.com" {
		t.Fatalf("email = %q, want %q", got, "user@example.com")
	}
	if got, _ := saved.Metadata["access_token"].(string); got != "access-token" {
		t.Fatalf("access_token = %q, want %q", got, "access-token")
	}
	if saved.LastRefreshedAt.IsZero() {
		t.Fatal("expected LastRefreshedAt to be populated from saved auth file")
	}
}

func TestIsRetryableCodexExchangeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "server error status", err: fmt.Errorf("token exchange failed with status 503: unavailable"), want: true},
		{name: "connection refused", err: fmt.Errorf("token exchange request failed: connection refused"), want: true},
		{name: "client error status", err: fmt.Errorf("token exchange failed with status 400: bad request"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetryableCodexExchangeError(tt.err); got != tt.want {
				t.Fatalf("retryable = %v, want %v", got, tt.want)
			}
		})
	}
}
