package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestSaveTokenRecordRegistersSavedFileBackedAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = sdkAuth.NewFileTokenStore()

	record := &coreauth.Auth{
		ID:       "codex-user@example.com-free.json",
		Provider: "codex",
		FileName: "codex-user@example.com-free.json",
		Metadata: map[string]any{
			"type":      "codex",
			"email":     "user@example.com",
			"proxy_url": "direct",
		},
	}

	savedPath, err := h.saveTokenRecord(context.Background(), record)
	if err != nil {
		t.Fatalf("saveTokenRecord returned error: %v", err)
	}
	if _, errStat := os.Stat(savedPath); errStat != nil {
		t.Fatalf("expected saved file at %s: %v", savedPath, errStat)
	}

	auth, ok := manager.GetByID(record.ID)
	if !ok || auth == nil {
		t.Fatalf("expected auth %q to be registered immediately", record.ID)
	}
	if auth.Provider != "codex" {
		t.Fatalf("provider = %q, want codex", auth.Provider)
	}
	if auth.ProxyURL != "direct" {
		t.Fatalf("proxy URL = %q, want direct", auth.ProxyURL)
	}
}

func TestGetAuthDiagnosticsReportsDiskOnlyAuths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	path := filepath.Join(authDir, "codex-disk-only.json")
	if err := os.WriteFile(path, []byte(`{"type":"codex","email":"disk-only@example.com"}`), 0o600); err != nil {
		t.Fatalf("failed to write auth file: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/diagnostics?provider=codex", nil)

	h.GetAuthDiagnostics(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var payload authDiagnostics
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if payload.Provider != "codex" {
		t.Fatalf("provider = %q, want codex", payload.Provider)
	}
	if payload.DiskSynthAuths != 1 {
		t.Fatalf("disk_synth_auths = %d, want 1", payload.DiskSynthAuths)
	}
	if payload.LoadedFileBackedAuths != 0 {
		t.Fatalf("loaded_file_backed_auths = %d, want 0", payload.LoadedFileBackedAuths)
	}
	if payload.DiskOnlyAuths != 1 {
		t.Fatalf("disk_only_auths = %d, want 1", payload.DiskOnlyAuths)
	}
	if len(payload.DiskOnlyAuthSample) == 0 || payload.DiskOnlyAuthSample[0] != "codex-disk-only.json" {
		t.Fatalf("unexpected disk_only_auth_sample: %#v", payload.DiskOnlyAuthSample)
	}
}
