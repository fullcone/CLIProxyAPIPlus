package management

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type trackingTokenStore struct {
	memoryAuthStore
	deleted []string
}

func (s *trackingTokenStore) Delete(ctx context.Context, id string) error {
	s.deleted = append(s.deleted, id)
	return s.memoryAuthStore.Delete(ctx, id)
}

func TestCodexCleanupRoundAutoDeletesPermanentInvalidAuth(t *testing.T) {
	authDir := t.TempDir()
	fileName := filepath.Join("nested", "user.json")
	fullPath := filepath.Join(authDir, fileName)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		t.Fatalf("failed to create auth subdir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(`{"type":"codex","email":"user@example.com"}`), 0o600); err != nil {
		t.Fatalf("failed to write auth file: %v", err)
	}

	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "codex",
		Status:   coreauth.StatusError,
		LastError: &coreauth.Error{
			Message: "token has been invalidated by upstream",
		},
		Metadata: map[string]any{"email": "user@example.com"},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("failed to register auth: %v", err)
	}

	store := &trackingTokenStore{}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = store

	h.runCodexCleanupRound(context.Background())

	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Fatalf("expected auth file to be removed, stat err: %v", err)
	}
	if len(store.deleted) != 1 || store.deleted[0] != fileName {
		t.Fatalf("expected token store delete for %q, got %#v", fileName, store.deleted)
	}
	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatalf("expected auth %q to remain addressable after cleanup", auth.ID)
	}
	if !updated.Disabled || updated.Status != coreauth.StatusDisabled {
		t.Fatalf("expected auth to be disabled after cleanup, got disabled=%v status=%s", updated.Disabled, updated.Status)
	}
	if h.codexCleanupRounds != 1 || h.codexCleanupTotalAutoDeleted != 1 {
		t.Fatalf("unexpected cleanup lifetime stats: rounds=%d autoDeleted=%d", h.codexCleanupRounds, h.codexCleanupTotalAutoDeleted)
	}
	if len(h.codexInvalidCounts) != 0 {
		t.Fatalf("expected invalid counter map to be cleared, got %#v", h.codexInvalidCounts)
	}
}

func TestCodexCleanupRoundCleansDisabledAuthAndResetsRecoveredCounter(t *testing.T) {
	authDir := t.TempDir()
	disabledFile := filepath.Join("disabled", "user.json")
	disabledPath := filepath.Join(authDir, disabledFile)
	if err := os.MkdirAll(filepath.Dir(disabledPath), 0o700); err != nil {
		t.Fatalf("failed to create disabled auth subdir: %v", err)
	}
	if err := os.WriteFile(disabledPath, []byte(`{"type":"codex","email":"disabled@example.com"}`), 0o600); err != nil {
		t.Fatalf("failed to write disabled auth file: %v", err)
	}

	manager := coreauth.NewManager(nil, nil, nil)
	disabledAuth := &coreauth.Auth{
		ID:       disabledFile,
		FileName: disabledFile,
		Provider: "codex",
		Disabled: true,
		Status:   coreauth.StatusDisabled,
		Metadata: map[string]any{"email": "disabled@example.com"},
	}
	if _, err := manager.Register(context.Background(), disabledAuth); err != nil {
		t.Fatalf("failed to register disabled auth: %v", err)
	}

	recoveringAuth := &coreauth.Auth{
		ID:       "recovering.json",
		FileName: "recovering.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"email": "recovering@example.com"},
	}
	if _, err := manager.Register(context.Background(), recoveringAuth); err != nil {
		t.Fatalf("failed to register recovering auth: %v", err)
	}

	store := &trackingTokenStore{}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = store
	h.codexInvalidCounts[recoveringAuth.ID] = 1

	h.runCodexCleanupRound(context.Background())

	if _, err := os.Stat(disabledPath); !os.IsNotExist(err) {
		t.Fatalf("expected disabled auth file to be removed, stat err: %v", err)
	}
	if h.codexCleanupTotalDisabledCleaned != 1 {
		t.Fatalf("expected one disabled cleanup, got %d", h.codexCleanupTotalDisabledCleaned)
	}
	if h.codexCleanupTotalRecovered != 1 {
		t.Fatalf("expected one recovered counter reset, got %d", h.codexCleanupTotalRecovered)
	}
	if len(store.deleted) == 0 {
		t.Fatal("expected token store deletion during disabled cleanup")
	}
	if _, ok := h.codexInvalidCounts[recoveringAuth.ID]; ok {
		t.Fatalf("expected recovered auth counter to be reset, got %#v", h.codexInvalidCounts)
	}
}
