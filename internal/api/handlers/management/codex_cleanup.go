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

// permanentErrorPatterns defines substrings that indicate a permanently invalid token.
var permanentErrorPatterns = [][2]string{
	{"token refresh failed", "invalid_grant"},
	{"token refresh failed", "status 403"},
	{"token refresh failed", "status 401"},
}

// permanentErrorSingle defines single-substring patterns for permanent failure.
var permanentErrorSingle = []string{
	"token has been invalidated",
	"token is expired",
}

const (
	codexCleanupInitialDelay = 30 * time.Second
	codexCleanupInterval     = 5 * time.Minute
	codexCleanupThreshold    = 3
	codexRefreshOKWindow     = 10 * time.Minute
)

// lifetime counters (package-level)
var (
	lifetimeRounds              int
	lifetimeTotalAutoDeleted    int
	lifetimeTotalRecovered      int
	lifetimeTotalDisabledCleaned int
)

var codexCleanupOnce sync.Once

// StartCodexCleanup launches the background Codex account cleanup loop.
// It is safe to call multiple times; only the first invocation starts the goroutine.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	codexCleanupOnce.Do(func() {
		go h.codexCleanupLoop(ctx)
	})
}

func (h *Handler) codexCleanupLoop(ctx context.Context) {
	// Wait for auth manager to finish loading.
	select {
	case <-time.After(codexCleanupInitialDelay):
	case <-ctx.Done():
		return
	}

	// invalidCounts tracks consecutive permanent-failure detections per auth ID.
	invalidCounts := make(map[string]int)

	// Run first scan immediately, then every codexCleanupInterval.
	h.codexCleanupRound(ctx, invalidCounts)

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.codexCleanupRound(ctx, invalidCounts)
		case <-ctx.Done():
			return
		}
	}
}

func (h *Handler) codexCleanupRound(ctx context.Context, invalidCounts map[string]int) {
	if h == nil || h.authManager == nil {
		return
	}

	lifetimeRounds++

	allAuths := h.authManager.List()

	// Filter codex accounts only.
	var codexAuths []*coreauth.Auth
	for _, a := range allAuths {
		if strings.ToLower(a.Provider) == "codex" {
			codexAuths = append(codexAuths, a)
		}
	}

	total := len(codexAuths)
	log.Debugf("codex cleanup: scanning %d codex accounts", total)

	var (
		statActive          int
		statRefreshOK       int
		statError           int
		statQuotaExceeded   int
		statDisabled        int
		statDisabledCleaned int

		newInvalid   int
		knownInvalid int
		autoDeleted  int
	)

	now := time.Now()
	seenIDs := make(map[string]struct{}, total)

	for _, auth := range codexAuths {
		seenIDs[auth.ID] = struct{}{}

		// --- Stats: count statuses ---
		switch auth.Status {
		case coreauth.StatusActive:
			statActive++
			if !auth.LastRefreshedAt.IsZero() && now.Sub(auth.LastRefreshedAt) <= codexRefreshOKWindow {
				statRefreshOK++
			}
		case coreauth.StatusError:
			statError++
		}
		if auth.Quota.Exceeded {
			statQuotaExceeded++
		}
		if auth.Disabled {
			statDisabled++
		}

		// --- Disabled accounts: clean up residual files ---
		if auth.Disabled {
			fileName := auth.FileName
			if fileName == "" {
				fileName = auth.ID
			}
			var filePath string
			if filepath.IsAbs(fileName) {
				filePath = fileName
			} else {
				filePath = filepath.Join(h.cfg.AuthDir, fileName)
			}

			removeErr := os.Remove(filePath)
			var removeResult string
			switch {
			case removeErr == nil:
				removeResult = "removed"
			case os.IsNotExist(removeErr):
				removeResult = "file not found"
			default:
				removeResult = removeErr.Error()
				log.Warnf("codex cleanup: failed to remove file %s for disabled account %s: %v", filePath, auth.ID, removeErr)
			}

			_ = h.deleteTokenRecord(ctx, fileName)

			email := ""
			if auth.Metadata != nil {
				if e, ok := auth.Metadata["email"].(string); ok {
					email = e
				}
			}
			log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record (file=%s, result=%s)", auth.ID, email, filePath, removeResult)

			statDisabledCleaned++
			continue
		}

		// --- Skip quota-exceeded accounts ---
		if auth.Quota.Exceeded {
			continue
		}

		// --- Only inspect StatusError with a LastError ---
		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			continue
		}

		msg := auth.LastError.Message
		if !isPermanentCodexError(msg) {
			// Was previously counted? Reset.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				email := ""
				if auth.Metadata != nil {
					if e, ok2 := auth.Metadata["email"].(string); ok2 {
						email = e
					}
				}
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// Permanent error detected — increment counter.
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]

		email := ""
		if auth.Metadata != nil {
			if e, ok := auth.Metadata["email"].(string); ok {
				email = e
			}
		}

		if count == 1 {
			newInvalid++
		} else {
			knownInvalid++
		}

		if count >= codexCleanupThreshold {
			// Auto-delete.
			fileName := auth.FileName
			if fileName == "" {
				fileName = auth.ID
			}
			var filePath string
			if filepath.IsAbs(fileName) {
				filePath = fileName
			} else {
				filePath = filepath.Join(h.cfg.AuthDir, fileName)
			}

			removeErr := os.Remove(filePath)
			if removeErr != nil && !os.IsNotExist(removeErr) {
				log.Warnf("codex cleanup: failed to remove file %s for account %s: %v", filePath, auth.ID, removeErr)
			}
			_ = h.deleteTokenRecord(ctx, fileName)
			h.disableAuth(ctx, auth.ID)

			log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s", auth.ID, email, codexCleanupThreshold, msg)

			delete(invalidCounts, auth.ID)
			autoDeleted++
			lifetimeTotalAutoDeleted++
		} else {
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", auth.ID, email, count, codexCleanupThreshold, msg)
		}
	}

	// Purge counters for IDs no longer present.
	for id := range invalidCounts {
		if _, exists := seenIDs[id]; !exists {
			delete(invalidCounts, id)
		}
	}

	lifetimeTotalDisabledCleaned += statDisabledCleaned

	totalInvalid := newInvalid + knownInvalid
	if totalInvalid > 0 || autoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", totalInvalid, newInvalid, knownInvalid, autoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		total, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		lifetimeRounds, lifetimeTotalAutoDeleted, lifetimeTotalRecovered, lifetimeTotalDisabledCleaned)
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
