package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type inFlightTestExecutor struct {
	mu           sync.Mutex
	executeAuths []string
	streamAuths  []string
	streamFinish chan struct{}
}

func (e *inFlightTestExecutor) Identifier() string { return "codex" }

func (e *inFlightTestExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if auth != nil {
		e.executeAuths = append(e.executeAuths, auth.ID)
	}
	return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
}

func (e *inFlightTestExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.mu.Lock()
	if auth != nil {
		e.streamAuths = append(e.streamAuths, auth.ID)
	}
	finish := e.streamFinish
	e.mu.Unlock()

	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(`{"type":"response.output_text.delta"}`)}
	go func() {
		if finish != nil {
			<-finish
		}
		close(chunks)
	}()
	return &cliproxyexecutor.StreamResult{Headers: http.Header{}, Chunks: chunks}, nil
}

func (e *inFlightTestExecutor) Refresh(context.Context, *Auth) (*Auth, error) {
	return nil, nil
}

func (e *inFlightTestExecutor) CountTokens(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if auth != nil {
		e.executeAuths = append(e.executeAuths, auth.ID)
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"count":1}`)}, nil
}

func (e *inFlightTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *inFlightTestExecutor) ExecuteAuths() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.executeAuths...)
}

func (e *inFlightTestExecutor) StreamAuths() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.streamAuths...)
}

func TestManager_ExecuteMixedOnce_SkipsCodexAuthAlreadyInFlight(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	executor := &inFlightTestExecutor{}
	manager.RegisterExecutor(executor)

	authA := &Auth{ID: "codex-a", Provider: "codex"}
	authB := &Auth{ID: "codex-b", Provider: "codex"}
	if _, err := manager.Register(context.Background(), authA); err != nil {
		t.Fatalf("register authA: %v", err)
	}
	if _, err := manager.Register(context.Background(), authB); err != nil {
		t.Fatalf("register authB: %v", err)
	}

	lease, _, _, ok := manager.tryReserveAuthExecution(authA)
	if !ok || lease == nil {
		t.Fatalf("expected to reserve authA")
	}
	defer lease.Release()

	resp, err := manager.executeMixedOnce(context.Background(), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}, 1)
	if err != nil {
		t.Fatalf("executeMixedOnce error: %v", err)
	}
	if string(resp.Payload) != "ok" {
		t.Fatalf("payload = %q, want ok", string(resp.Payload))
	}
	got := executor.ExecuteAuths()
	if len(got) != 1 || got[0] != "codex-b" {
		t.Fatalf("execute auths = %v, want [codex-b]", got)
	}
}

func TestManager_ExecuteStreamMixedOnce_ReleasesCodexLeaseAfterStreamCloses(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	executor := &inFlightTestExecutor{streamFinish: make(chan struct{})}
	manager.RegisterExecutor(executor)

	auth := &Auth{ID: "codex-stream", Provider: "codex"}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	result, err := manager.executeStreamMixedOnce(context.Background(), []string{"codex"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}, 1)
	if err != nil {
		t.Fatalf("executeStreamMixedOnce error: %v", err)
	}
	if got := manager.authExecutionInFlightCount(auth.ID); got != 1 {
		t.Fatalf("in-flight count before drain = %d, want 1", got)
	}

	first, ok := <-result.Chunks
	if !ok {
		t.Fatalf("expected first stream chunk")
	}
	if len(first.Payload) == 0 {
		t.Fatalf("expected non-empty first payload")
	}

	close(executor.streamFinish)
	for range result.Chunks {
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := manager.authExecutionInFlightCount(auth.ID); got == 0 {
			streamAuths := executor.StreamAuths()
			if len(streamAuths) != 1 || streamAuths[0] != auth.ID {
				t.Fatalf("stream auths = %v, want [%s]", streamAuths, auth.ID)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected in-flight count to return to 0, got %d", manager.authExecutionInFlightCount(auth.ID))
}
