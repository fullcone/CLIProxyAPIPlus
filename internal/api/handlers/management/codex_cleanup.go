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

// permanentErrorPatterns defines substrings in LastError.Message that indicate
// a Codex OAuth token is permanently invalid and will never recover.
var permanentErrorPatterns = [][2]string{
	{"token refresh failed", "invalid_grant"},
	{"token refresh failed", "status 403"},
	{"token refresh failed", "status 401"},
}

// permanentErrorSingle defines single-substring patterns.
var permanentErrorSingle = []string{
	"token has been invalidated",
	"token is expired",
	"account has been deactivated",
}

// Package-level lifetime counters.
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
	// Wait 30 seconds for auth manager to finish loading.
	select {
	case <-time.After(30 * time.Second):
	case <-ctx.Done():
		return
	}

	// invalidCounts tracks consecutive permanent-error detections per auth ID.
	invalidCounts := make(map[string]int)

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	h.codexCleanupRound(ctx, invalidCounts)
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

		_, email := auth.AccountInfo()

		// --- Disabled accounts: clean up residual files ---
		if auth.Disabled {
			statDisabled++
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
			err := os.Remove(filePath)
			if err == nil {
				statDisabledCleaned++
				log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record", auth.ID, email)
			} else if !os.IsNotExist(err) {
				log.Warnf("codex cleanup: failed to remove file for disabled account %s (%s): %v", auth.ID, email, err)
			}
			_ = h.deleteTokenRecord(ctx, fileName)
			continue
		}

		// Track status counters.
		switch auth.Status {
		case coreauth.StatusActive:
			statActive++
			if !auth.LastRefreshedAt.IsZero() && now.Sub(auth.LastRefreshedAt) <= 10*time.Minute {
				statRefreshOK++
			}
		case coreauth.StatusError:
			statError++
		}

		if auth.Quota.Exceeded {
			statQuotaExceeded++
			continue
		}

		// Only inspect accounts in error state with a recorded error.
		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			// Account is not in permanent-error territory; reset if previously tracked.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// Check if the error message matches any permanent-error pattern.
		reason := matchPermanentError(auth.LastError.Message)
		if reason == "" {
			// Not a permanent error; reset counter if needed.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// Increment consecutive invalid count.
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]
		log.Debugf("codex cleanup: %s (%s) invalid count %d/1 — reason: %s", auth.ID, email, count, reason)

		if count >= 1 {
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
			_ = os.Remove(filePath)
			_ = h.deleteTokenRecord(ctx, fileName)
			h.disableAuth(ctx, auth.ID)
			delete(invalidCounts, auth.ID)
			autoDeleted++
			lifetimeTotalAutoDeleted++
			log.Warnf("codex cleanup: auto-deleted %s (%s) after 1 check — reason: %s", auth.ID, email, reason)
			newInvalid++
		} else {
			knownInvalid++
		}
	}

	// Update lifetime disabled-cleaned counter.
	lifetimeTotalDisabledCleaned += statDisabledCleaned

	// Purge counters for IDs no longer present.
	for id := range invalidCounts {
		if _, ok := seenIDs[id]; !ok {
			delete(invalidCounts, id)
		}
	}

	// Count remaining known-invalid entries.
	knownInvalid = len(invalidCounts)

	totalInvalid := newInvalid + knownInvalid
	if totalInvalid > 0 || autoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", totalInvalid, newInvalid, knownInvalid, autoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		total, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		lifetimeRounds, lifetimeTotalAutoDeleted, lifetimeTotalRecovered, lifetimeTotalDisabledCleaned)
}

// matchPermanentError checks if msg matches any known permanent-error pattern.
// Returns a human-readable reason string, or "" if no match.
func matchPermanentError(msg string) string {
	lower := strings.ToLower(msg)
	for _, pair := range permanentErrorPatterns {
		if strings.Contains(lower, pair[0]) && strings.Contains(lower, pair[1]) {
			return msg
		}
	}
	for _, pat := range permanentErrorSingle {
		if strings.Contains(lower, pat) {
			return msg
		}
	}
	return ""
}
