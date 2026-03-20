package management

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

const authDiagnosticsSampleLimit = 20

type authDiagnostics struct {
	Provider              string   `json:"provider"`
	DiskJSONFiles         int      `json:"disk_json_files"`
	DiskNonEmptyJSONFiles int      `json:"disk_non_empty_json_files"`
	DiskParsedJSONFiles   int      `json:"disk_parsed_json_files"`
	DiskProviderFiles     int      `json:"disk_provider_files"`
	DiskSynthAuths        int      `json:"disk_synth_auths"`
	LoadedAuths           int      `json:"loaded_auths"`
	LoadedFileBackedAuths int      `json:"loaded_file_backed_auths"`
	DiskOnlyAuths         int      `json:"disk_only_auths"`
	DiskOnlyAuthSample    []string `json:"disk_only_auth_sample"`
	LoadedOnlyFileBacked  int      `json:"loaded_only_file_backed_auths"`
	LoadedOnlyFileSample  []string `json:"loaded_only_file_backed_sample"`
}

func normalizeDiagnosticsProvider(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "gemini" {
		return "gemini-cli"
	}
	return p
}

func authMatchesDiagnosticsProvider(auth *coreauth.Auth, provider string) bool {
	if auth == nil {
		return false
	}
	if provider == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(auth.Provider), provider)
}

func fileMetadataMatchesDiagnosticsProvider(metadata map[string]any, provider string) bool {
	if provider == "" {
		return true
	}
	raw, _ := metadata["type"].(string)
	return normalizeDiagnosticsProvider(raw) == provider
}

func sampleSortedKeys(values map[string]string, limit int) []string {
	if len(values) == 0 || limit <= 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > limit {
		keys = keys[:limit]
	}
	return keys
}

func (h *Handler) collectAuthDiagnostics(providerFilter string) (*authDiagnostics, error) {
	if h == nil || h.cfg == nil {
		return nil, os.ErrInvalid
	}
	authDir := strings.TrimSpace(h.cfg.AuthDir)
	if authDir == "" {
		return nil, os.ErrInvalid
	}

	providerFilter = normalizeDiagnosticsProvider(providerFilter)
	diag := &authDiagnostics{Provider: providerFilter}

	sctx := &synthesizer.SynthesisContext{
		Config:      h.cfg,
		AuthDir:     authDir,
		Now:         time.Now(),
		IDGenerator: synthesizer.NewStableIDGenerator(),
	}

	diskAuthIDs := make(map[string]string)
	if errWalk := filepath.WalkDir(authDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}

		diag.DiskJSONFiles++

		data, errRead := os.ReadFile(path)
		if errRead != nil {
			return nil
		}
		if len(data) == 0 {
			return nil
		}
		diag.DiskNonEmptyJSONFiles++

		var metadata map[string]any
		if errParse := json.Unmarshal(data, &metadata); errParse != nil {
			return nil
		}
		diag.DiskParsedJSONFiles++
		if fileMetadataMatchesDiagnosticsProvider(metadata, providerFilter) {
			diag.DiskProviderFiles++
		}

		auths := synthesizer.SynthesizeAuthFile(sctx, path, data)
		for _, auth := range auths {
			if !authMatchesDiagnosticsProvider(auth, providerFilter) {
				continue
			}
			diag.DiskSynthAuths++
			diskAuthIDs[auth.ID] = path
		}
		return nil
	}); errWalk != nil {
		return nil, errWalk
	}

	loadedFileBacked := make(map[string]string)
	loadedOnly := make(map[string]string)
	if h.authManager != nil {
		for _, auth := range h.authManager.List() {
			if !authMatchesDiagnosticsProvider(auth, providerFilter) {
				continue
			}
			diag.LoadedAuths++
			path := strings.TrimSpace(authAttribute(auth, "path"))
			if path == "" {
				continue
			}
			diag.LoadedFileBackedAuths++
			loadedFileBacked[auth.ID] = path
		}
	}

	diskOnly := make(map[string]string)
	for id, path := range diskAuthIDs {
		if _, ok := loadedFileBacked[id]; !ok {
			diskOnly[id] = path
		}
	}
	for id, path := range loadedFileBacked {
		if _, ok := diskAuthIDs[id]; !ok {
			loadedOnly[id] = path
		}
	}

	diag.DiskOnlyAuths = len(diskOnly)
	diag.DiskOnlyAuthSample = sampleSortedKeys(diskOnly, authDiagnosticsSampleLimit)
	diag.LoadedOnlyFileBacked = len(loadedOnly)
	diag.LoadedOnlyFileSample = sampleSortedKeys(loadedOnly, authDiagnosticsSampleLimit)

	return diag, nil
}

func (h *Handler) GetAuthDiagnostics(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "handler unavailable"})
		return
	}
	diag, err := h.collectAuthDiagnostics(c.Query("provider"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, diag)
}
