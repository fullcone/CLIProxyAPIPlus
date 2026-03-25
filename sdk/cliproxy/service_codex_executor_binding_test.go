package cliproxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func TestEnsureExecutorsForAuth_CodexDoesNotReplaceInNormalMode(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}
	auth := &coreauth.Auth{
		ID:       "codex-auth-1",
		Provider: "codex",
		Status:   coreauth.StatusActive,
	}

	service.ensureExecutorsForAuth(auth)
	firstExecutor, okFirst := service.coreManager.Executor("codex")
	if !okFirst || firstExecutor == nil {
		t.Fatal("expected codex executor after first bind")
	}

	service.ensureExecutorsForAuth(auth)
	secondExecutor, okSecond := service.coreManager.Executor("codex")
	if !okSecond || secondExecutor == nil {
		t.Fatal("expected codex executor after second bind")
	}

	if firstExecutor != secondExecutor {
		t.Fatal("expected codex executor to stay unchanged in normal mode")
	}
}

func TestEnsureExecutorsForAuthWithMode_CodexForceReplace(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}
	auth := &coreauth.Auth{
		ID:       "codex-auth-2",
		Provider: "codex",
		Status:   coreauth.StatusActive,
	}

	service.ensureExecutorsForAuth(auth)
	firstExecutor, okFirst := service.coreManager.Executor("codex")
	if !okFirst || firstExecutor == nil {
		t.Fatal("expected codex executor after first bind")
	}

	service.ensureExecutorsForAuthWithMode(auth, true)
	secondExecutor, okSecond := service.coreManager.Executor("codex")
	if !okSecond || secondExecutor == nil {
		t.Fatal("expected codex executor after forced rebind")
	}

	if firstExecutor == secondExecutor {
		t.Fatal("expected codex executor replacement in force mode")
	}
}

func TestWaitForInitialAuthPipelineStableWaitsForWatcherAndServiceBacklogs(t *testing.T) {
	var watcherPending atomic.Int64
	var watcherDispatching atomic.Int64

	service := &Service{
		authUpdates: make(chan watcher.AuthUpdate, 1),
		watcher: &WatcherWrapper{
			pendingAuthUpdateCount: func() int {
				return int(watcherPending.Load())
			},
			dispatchingAuthUpdateCount: func() int {
				return int(watcherDispatching.Load())
			},
		},
	}
	service.authApplyInFlight.Store(1)
	watcherPending.Store(1)
	watcherDispatching.Store(1)
	service.authUpdates <- watcher.AuthUpdate{ID: "auth-1"}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- service.waitForInitialAuthPipelineStable(ctx)
	}()

	select {
	case err := <-done:
		t.Fatalf("waitForInitialAuthPipelineStable returned too early: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	<-service.authUpdates
	service.authApplyInFlight.Store(0)
	watcherPending.Store(0)
	watcherDispatching.Store(0)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitForInitialAuthPipelineStable returned error: %v", err)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("waitForInitialAuthPipelineStable did not return after pipeline drained")
	}
}
