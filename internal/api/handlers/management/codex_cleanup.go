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
// Each entry is a pair of substrings that must both appear in LastError.Message.
var permanentErrorPatterns = [][2]string{
	{"token refresh failed", "invalid_grant"},
	{"token refresh failed", "status 403"},
	{"token refresh failed", "status 401"},
	{"token has been invalidated", ""},
	{"token is expired", ""},
}

const (
	codexCleanupInitialDelay = 30 * time.Second
	codexCleanupInterval     = 5 * time.Minute
	codexCleanupThreshold    = 3
	codexRefreshOKWindow     = 10 * time.Minute
)

// Package-level lifetime counters.
var (
	lifetimeRounds              int
	lifetimeTotalAutoDeleted    int
	lifetimeTotalRecovered      int
	lifetimeTotalDisabledCleaned int
)

var codexCleanupOnce sync.Once

// StartCodexCleanup launches the background codex cleanup goroutine.
// It is safe to call multiple times; only the first invocation starts the loop.
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

	// invalidCounts tracks consecutive permanent-error detections per auth ID.
	invalidCounts := make(map[string]int)

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()

	for {
		h.codexCleanupRound(ctx, invalidCounts)

		select {
		case <-ticker.C:
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

	// Collect codex accounts only.
	var codexAuths []*coreauth.Auth
	for _, a := range allAuths {
		if strings.ToLower(a.Provider) == "codex" {
			codexAuths = append(codexAuths, a)
		}
	}

	total := len(codexAuths)
	log.Debugf("codex cleanup: scanning %d codex accounts", total)

	// Per-round statistics.
	var (
		statActive           int
		statRefreshOK        int
		statError            int
		statQuotaExceeded    int
		statDisabled         int
		statDisabledCleaned  int
		statAutoDeleted      int
		newInvalid           int
		knownInvalid         int
	)

	// Track which IDs are seen this round so we can detect recoveries.
	seenIDs := make(map[string]bool, total)

	now := time.Now()

	for _, auth := range codexAuths {
		seenIDs[auth.ID] = true

		// Count status statistics.
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

		// --- Disabled account: clean up residual files ---
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

			err := os.Remove(filePath)
			if err == nil {
				statDisabledCleaned++
				_ = h.deleteTokenRecord(ctx, fileName)
				log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record (%s)", auth.ID, authEmail(auth), filePath)
			} else if !os.IsNotExist(err) {
				log.Warnf("codex cleanup: failed to remove file for disabled account %s (%s): %v", auth.ID, authEmail(auth), err)
			} else {
				// File already gone — still try to clean token record silently.
				_ = h.deleteTokenRecord(ctx, fileName)
			}
			continue
		}

		// --- Skip quota-exceeded accounts ---
		if auth.Quota.Exceeded {
			continue
		}

		// --- Only inspect StatusError with a LastError ---
		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			// Account is healthy — if it was previously counted, reset.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				delete(invalidCounts, auth.ID)
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, authEmail(auth))
				lifetimeTotalRecovered++
			}
			continue
		}

		// --- Check for permanent error ---
		msg := auth.LastError.Message
		reason := matchPermanentError(msg)
		if reason == "" {
			// Error but not permanent — reset if previously counted.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				delete(invalidCounts, auth.ID)
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, authEmail(auth))
				lifetimeTotalRecovered++
			}
			continue
		}

		// Increment consecutive count.
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]

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

			_ = os.Remove(filePath)
			_ = h.deleteTokenRecord(ctx, fileName)
			h.disableAuth(ctx, auth.ID)
			delete(invalidCounts, auth.ID)

			statAutoDeleted++
			lifetimeTotalAutoDeleted++
			newInvalid++
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

	// Detect recoveries for IDs that disappeared from the list.
	for id, cnt := range invalidCounts {
		if !seenIDs[id] && cnt > 0 {
			delete(invalidCounts, id)
			// No recovery log — account simply gone.
		}
	}

	lifetimeTotalDisabledCleaned += statDisabledCleaned

	// Summary with changes.
	permanentlyInvalid := newInvalid + knownInvalid
	if permanentlyInvalid > 0 || statAutoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", permanentlyInvalid, newInvalid, knownInvalid, statAutoDeleted)
	}

	// Always output summary.
	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		total, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		lifetimeRounds, lifetimeTotalAutoDeleted, lifetimeTotalRecovered, lifetimeTotalDisabledCleaned)
}

// matchPermanentError checks whether msg matches any permanent error pattern.
// Returns a human-readable reason string, or "" if no match.
func matchPermanentError(msg string) string {
	lower := strings.ToLower(msg)
	for _, pat := range permanentErrorPatterns {
		first := strings.ToLower(pat[0])
		if !strings.Contains(lower, first) {
			continue
		}
		if pat[1] == "" {
			return pat[0]
		}
		second := strings.ToLower(pat[1])
		if strings.Contains(lower, second) {
			return pat[0] + " + " + pat[1]
		}
	}
	return ""
}

