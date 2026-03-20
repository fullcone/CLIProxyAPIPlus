package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type countingTokenStore struct {
	inner *sdkAuth.FileTokenStore
	mu    sync.Mutex
	saves int
}

func (s *countingTokenStore) SetBaseDir(dir string) {
	if s == nil || s.inner == nil {
		return
	}
	s.inner.SetBaseDir(dir)
}

func (s *countingTokenStore) List(ctx context.Context) ([]*coreauth.Auth, error) {
	return s.inner.List(ctx)
}

func (s *countingTokenStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	s.mu.Lock()
	s.saves++
	s.mu.Unlock()
	return s.inner.Save(ctx, auth)
}

func (s *countingTokenStore) Delete(ctx context.Context, id string) error {
	return s.inner.Delete(ctx, id)
}

func (s *countingTokenStore) SaveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saves
}

func waitForRegisteredAuth(t *testing.T, manager *coreauth.Manager, id string, timeout time.Duration) *coreauth.Auth {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if auth, ok := manager.GetByID(id); ok && auth != nil {
			return auth
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for auth %q to be registered", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSaveTokenRecordRegistersSavedFileBackedAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	store := &countingTokenStore{inner: sdkAuth.NewFileTokenStore()}
	manager.SetStore(store)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = store

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

	auth := waitForRegisteredAuth(t, manager, record.ID, time.Second)
	if auth.Provider != "codex" {
		t.Fatalf("provider = %q, want codex", auth.Provider)
	}
	if auth.ProxyURL != "direct" {
		t.Fatalf("proxy URL = %q, want direct", auth.ProxyURL)
	}
	if got := store.SaveCount(); got != 1 {
		t.Fatalf("save count = %d, want 1 (store.Save only once during saveTokenRecord)", got)
	}
}

func TestSaveTokenRecordFallsBackToSyncWhenImmediateQueueFull(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	store := &countingTokenStore{inner: sdkAuth.NewFileTokenStore()}
	manager.SetStore(store)
	h := &Handler{
		cfg:                &config.Config{AuthDir: authDir},
		authManager:        manager,
		tokenStore:         store,
		immediateAuthQueue: make(chan string, 1),
		immediateAuthDirty: make(map[string]bool),
	}
	h.immediateAuthQueue <- "busy"

	record := &coreauth.Auth{
		ID:       "codex-sync-fallback@example.com-free.json",
		Provider: "codex",
		FileName: "codex-sync-fallback@example.com-free.json",
		Metadata: map[string]any{
			"type":  "codex",
			"email": "sync-fallback@example.com",
		},
	}

	if _, err := h.saveTokenRecord(context.Background(), record); err != nil {
		t.Fatalf("saveTokenRecord returned error: %v", err)
	}

	if auth, ok := manager.GetByID(record.ID); !ok || auth == nil {
		t.Fatalf("expected auth %q to be registered via sync fallback", record.ID)
	}
	if got := store.SaveCount(); got != 1 {
		t.Fatalf("save count = %d, want 1 (sync fallback should still avoid duplicate persistence)", got)
	}
}

func TestImmediateAuthRegistrationQueueCoalescesDirtyPaths(t *testing.T) {
	h := &Handler{
		authManager:        coreauth.NewManager(nil, nil, nil),
		immediateAuthQueue: make(chan string, 1),
		immediateAuthDirty: make(map[string]bool),
	}

	if ok := h.enqueueImmediateAuthRegistration("a.json"); !ok {
		t.Fatal("expected first enqueue to succeed")
	}
	if got := len(h.immediateAuthQueue); got != 1 {
		t.Fatalf("queue length after first enqueue = %d, want 1", got)
	}
	if dirty := h.immediateAuthDirty["a.json"]; dirty {
		t.Fatal("expected first enqueue to mark path as clean")
	}

	if ok := h.enqueueImmediateAuthRegistration("a.json"); !ok {
		t.Fatal("expected duplicate enqueue to coalesce")
	}
	if got := len(h.immediateAuthQueue); got != 1 {
		t.Fatalf("queue length after duplicate enqueue = %d, want 1", got)
	}
	if dirty := h.immediateAuthDirty["a.json"]; !dirty {
		t.Fatal("expected duplicate enqueue to mark path dirty")
	}

	if retry := h.finishImmediateAuthRegistration("a.json"); !retry {
		t.Fatal("expected dirty path to request one more processing pass")
	}
	if dirty := h.immediateAuthDirty["a.json"]; dirty {
		t.Fatal("expected dirty flag to be cleared after requesting retry")
	}

	if retry := h.finishImmediateAuthRegistration("a.json"); retry {
		t.Fatal("expected clean path to finish without retry")
	}
	if _, exists := h.immediateAuthDirty["a.json"]; exists {
		t.Fatal("expected path to be removed from pending map after completion")
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
