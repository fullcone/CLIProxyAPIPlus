package management

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// permanentErrorPatterns defines substrings that indicate a permanently invalid Codex token.
var permanentErrorPatterns = [][2]string{
	{"token refresh failed", "invalid_grant"},
	{"token refresh failed", "status 403"},
	{"token refresh failed", "status 401"},
}

// permanentErrorSingle defines single-substring patterns for permanent invalidity.
var permanentErrorSingle = []string{
	"token has been invalidated",
	"token is expired",
}

const (
	codexCleanupInitialDelay = 30 * time.Second
	codexCleanupInterval     = 5 * time.Minute
	codexCleanupThreshold    = 3
	codexCleanupRefreshOKWindow = 10 * time.Minute
)

var (
	codexCleanupOnce         sync.Once
	codexCleanupRounds       int
	codexCleanupTotalDeleted int
	codexCleanupTotalRecovered int
	codexCleanupTotalDisabledCleaned int
)

// StartCodexCleanup launches the background Codex account cleanup loop.
// It is safe to call multiple times; only the first invocation starts the goroutine.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	codexCleanupOnce.Do(func() {
		go h.codexCleanupLoop(ctx)
	})
}

func (h *Handler) codexCleanupLoop(ctx context.Context) {
	select {
	case <-time.After(codexCleanupInitialDelay):
	case <-ctx.Done():
		return
	}

	invalidCounts := make(map[string]int)

	h.runCodexCleanup(ctx, invalidCounts)

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.runCodexCleanup(ctx, invalidCounts)
		case <-ctx.Done():
			return
		}
	}
}

func (h *Handler) runCodexCleanup(ctx context.Context, invalidCounts map[string]int) {
	if h == nil || h.authManager == nil {
		return
	}

	codexCleanupRounds++

	all := h.authManager.List()
	var codexAuths []*coreauth.Auth
	for _, a := range all {
		if strings.ToLower(a.Provider) == "codex" {
			codexAuths = append(codexAuths, a)
		}
	}

	log.Debugf("codex cleanup: scanning %d codex accounts", len(codexAuths))

	now := time.Now()
	var (
		statTotal           = len(codexAuths)
		statActive          int
		statRefreshOK       int
		statError           int
		statQuotaExceeded   int
		statDisabled        int
		statDisabledCleaned int
		statAutoDeleted     int
		newInvalid          int
		knownInvalid        int
	)

	// Track which IDs are still permanently invalid this round.
	seenInvalid := make(map[string]bool)

	for _, auth := range codexAuths {
		// --- Disabled accounts: clean up residual files ---
		if auth.Disabled {
			statDisabled++
			fileName := strings.TrimSpace(auth.FileName)
			if fileName == "" {
				fileName = strings.TrimSpace(auth.ID)
			}
			if fileName != "" {
				filePath := fileName
				if !filepath.IsAbs(filePath) {
					filePath = filepath.Join(h.cfg.AuthDir, filePath)
				}
				err := os.Remove(filePath)
				if err == nil {
					statDisabledCleaned++
					log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record", auth.ID, authEmail(auth))
					_ = h.deleteTokenRecord(ctx, fileName)
				} else if !os.IsNotExist(err) {
					log.Warnf("codex cleanup: failed to remove file for disabled account %s: %v", auth.ID, err)
				} else {
					// File already gone — still try to clean token record silently.
					_ = h.deleteTokenRecord(ctx, fileName)
				}
			}
			continue
		}

		// --- Stats ---
		if auth.Status == coreauth.StatusActive {
			statActive++
			if !auth.LastRefreshedAt.IsZero() && now.Sub(auth.LastRefreshedAt) <= codexCleanupRefreshOKWindow {
				statRefreshOK++
			}
		}
		if auth.Status == coreauth.StatusError {
			statError++
		}
		if auth.Quota.Exceeded {
			statQuotaExceeded++
			continue
		}

		// --- Only inspect error-state accounts ---
		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			continue
		}

		if !isPermanentCodexError(auth.LastError.Message) {
			// Not permanently invalid — if it was tracked before, it recovered.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, authEmail(auth))
				delete(invalidCounts, auth.ID)
				codexCleanupTotalRecovered++
			}
			continue
		}

		// Permanently invalid.
		seenInvalid[auth.ID] = true
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]
		reason := auth.LastError.Message

		if count >= codexCleanupThreshold {
			// Auto-delete.
			fileName := strings.TrimSpace(auth.FileName)
			if fileName == "" {
				fileName = strings.TrimSpace(auth.ID)
			}
			if fileName != "" {
				filePath := fileName
				if !filepath.IsAbs(filePath) {
					filePath = filepath.Join(h.cfg.AuthDir, filePath)
				}
				_ = os.Remove(filePath)
				_ = h.deleteTokenRecord(ctx, fileName)
			}
			h.disableAuth(ctx, auth.ID)
			delete(invalidCounts, auth.ID)
			statAutoDeleted++
			codexCleanupTotalDeleted++
			log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s", auth.ID, authEmail(auth), codexCleanupThreshold, reason)
		} else {
			if count == 1 {
				newInvalid++
			} else {
				knownInvalid++
			}
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", auth.ID, authEmail(auth), count, codexCleanupThreshold, reason)
		}
	}

	// Reset counters for IDs that were previously tracked but no longer appear as invalid.
	for id, cnt := range invalidCounts {
		if cnt > 0 && !seenInvalid[id] {
			log.Infof("codex cleanup: %s recovered, resetting counter", id)
			delete(invalidCounts, id)
			codexCleanupTotalRecovered++
		}
	}

	codexCleanupTotalDisabledCleaned += statDisabledCleaned

	totalCurrentInvalid := newInvalid + knownInvalid
	if totalCurrentInvalid > 0 || statAutoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", totalCurrentInvalid, newInvalid, knownInvalid, statAutoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		statTotal, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		codexCleanupRounds, codexCleanupTotalDeleted, codexCleanupTotalRecovered, codexCleanupTotalDisabledCleaned)
}

// isPermanentCodexError checks whether the error message indicates a permanently invalid token.
func isPermanentCodexError(msg string) bool {
	lower := strings.ToLower(msg)
	for _, pair := range permanentErrorPatterns {
		if strings.Contains(lower, pair[0]) && strings.Contains(lower, pair[1]) {
			return true
		}
	}
	for _, pattern := range permanentErrorSingle {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

