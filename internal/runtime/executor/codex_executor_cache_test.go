package executor

import (
	"context"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v6/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestCodexExecutorCacheHelper_OpenAIChatCompletions_StablePromptCacheKeyFromAPIKey(t *testing.T) {
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Set("apiKey", "test-api-key")

	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	executor := &CodexExecutor{}
	rawJSON := []byte(`{"model":"gpt-5.3-codex","stream":true}`)
	req := cliproxyexecutor.Request{
		Model:   "gpt-5.3-codex",
		Payload: []byte(`{"model":"gpt-5.3-codex"}`),
	}
	url := "https://example.com/responses"

	httpReq, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON)
	if err != nil {
		t.Fatalf("cacheHelper error: %v", err)
	}

	body, errRead := io.ReadAll(httpReq.Body)
	if errRead != nil {
		t.Fatalf("read request body: %v", errRead)
	}

	expectedKey := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:test-api-key")).String()
	gotKey := gjson.GetBytes(body, "prompt_cache_key").String()
	if gotKey != expectedKey {
		t.Fatalf("prompt_cache_key = %q, want %q", gotKey, expectedKey)
	}
	if gotConversation := httpReq.Header.Get("Conversation_id"); gotConversation != expectedKey {
		t.Fatalf("Conversation_id = %q, want %q", gotConversation, expectedKey)
	}
	if gotSession := httpReq.Header.Get("Session_id"); gotSession != expectedKey {
		t.Fatalf("Session_id = %q, want %q", gotSession, expectedKey)
	}

	httpReq2, err := executor.cacheHelper(ctx, sdktranslator.FromString("openai"), url, req, rawJSON)
	if err != nil {
		t.Fatalf("cacheHelper error (second call): %v", err)
	}
	body2, errRead2 := io.ReadAll(httpReq2.Body)
	if errRead2 != nil {
		t.Fatalf("read request body (second call): %v", errRead2)
	}
	gotKey2 := gjson.GetBytes(body2, "prompt_cache_key").String()
	if gotKey2 != expectedKey {
		t.Fatalf("prompt_cache_key (second call) = %q, want %q", gotKey2, expectedKey)
	}
}

func TestCodexAuthCacheKey_ReusesNormalizedRouteIdentity(t *testing.T) {
	cfg := &config.Config{}
	authA := &cliproxyauth.Auth{ID: "codex-a", ProxyURL: "http://Proxy.EXAMPLE.com/"}
	authB := &cliproxyauth.Auth{ID: "codex-a", ProxyURL: "http://proxy.example.com:80"}

	keyA := codexAuthCacheKey(cfg, authA)
	keyB := codexAuthCacheKey(cfg, authB)
	if keyA != keyB {
		t.Fatalf("cache key mismatch: %q != %q", keyA, keyB)
	}
}

func TestCodexAuthCacheKey_SeparatesAuthIDAndDirectModes(t *testing.T) {
	cfg := &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "direct"}}

	keyInherit := codexAuthCacheKey(cfg, &cliproxyauth.Auth{ID: "codex-a"})
	keyExplicit := codexAuthCacheKey(cfg, &cliproxyauth.Auth{ID: "codex-a", ProxyURL: "none"})
	keyOtherAuth := codexAuthCacheKey(cfg, &cliproxyauth.Auth{ID: "codex-b", ProxyURL: "none"})

	if keyInherit == keyExplicit {
		t.Fatalf("expected inherit and explicit direct cache keys to differ, got %q", keyInherit)
	}
	if keyExplicit == keyOtherAuth {
		t.Fatalf("expected auth ID to isolate cache keys, got %q", keyExplicit)
	}
}

func TestCodexAuthConfigForRoute_UsesEffectiveProxyOverride(t *testing.T) {
	cfg := &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://global-proxy.example.com:8080"}}
	route := resolveProxyRouteIdentity(cfg, &cliproxyauth.Auth{ID: "codex-a", ProxyURL: "direct"})
	authCfg := codexAuthConfigForRoute(cfg, route)

	if authCfg == nil {
		t.Fatal("expected auth config")
	}
	if authCfg == cfg {
		t.Fatal("expected a cloned config when effective route overrides the global proxy")
	}
	if got := authCfg.ProxyURL; got != "direct" {
		t.Fatalf("proxy URL = %q, want %q", got, "direct")
	}
	if got := cfg.ProxyURL; got != "http://global-proxy.example.com:8080" {
		t.Fatalf("global proxy URL mutated to %q", got)
	}
}
