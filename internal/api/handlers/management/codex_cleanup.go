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
var permanentErrorPatterns = [][]string{
	{"token refresh failed", "invalid_grant"},
	{"token refresh failed", "status 403"},
	{"token refresh failed", "status 401"},
	{"token has been invalidated"},
	{"token is expired"},
}

// codex cleanup configuration constants
const (
	codexCleanupInitialDelay = 30 * time.Second
	codexCleanupInterval     = 5 * time.Minute
	codexCleanupThreshold    = 3
	codexRefreshOKWindow     = 10 * time.Minute
)

// package-level lifetime statistics
var (
	lifetimeRounds       int
	lifetimeTotalDeleted int
	lifetimeTotalRecover int
	lifetimeMu           sync.Mutex
)

var codexCleanupOnce sync.Once

// StartCodexCleanup launches the background goroutine that periodically scans
// Codex OAuth accounts and auto-deletes permanently invalid ones.
// It is safe to call multiple times; only the first invocation starts the loop.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	codexCleanupOnce.Do(func() {
		go h.codexCleanupLoop(ctx)
	})
}

func (h *Handler) codexCleanupLoop(ctx context.Context) {
	// invalidCounts tracks consecutive permanent-error detections per auth ID.
	invalidCounts := make(map[string]int)

	// Wait for auth manager to finish loading.
	select {
	case <-ctx.Done():
		return
	case <-time.After(codexCleanupInitialDelay):
	}

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()

	for {
		h.runCodexCleanupRound(ctx, invalidCounts)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (h *Handler) runCodexCleanupRound(ctx context.Context, invalidCounts map[string]int) {
	if h.authManager == nil {
		return
	}

	allAuths := h.authManager.List()

	// Filter codex accounts only.
	var codexAuths []*coreauth.Auth
	for _, a := range allAuths {
		if strings.ToLower(a.Provider) == "codex" {
			codexAuths = append(codexAuths, a)
		}
	}

	if len(codexAuths) == 0 {
		return
	}

	log.Debugf("codex cleanup: scanning %d codex accounts", len(codexAuths))

	now := time.Now()

	// Per-round statistics.
	var (
		statActive        int
		statRefreshOK     int
		statError         int
		statQuotaExceeded int
		statDisabled      int
	)

	// Track which IDs are still present this round for counter cleanup.
	seenIDs := make(map[string]struct{}, len(codexAuths))

	var (
		newInvalid   int
		knownInvalid int
		autoDeleted  int
		recovered    int
	)

	for _, a := range codexAuths {
		id := a.ID
		seenIDs[id] = struct{}{}

		// Gather summary stats.
		if a.Disabled {
			statDisabled++
		}
		if a.Quota.Exceeded {
			statQuotaExceeded++
		}
		if a.Status == coreauth.StatusActive {
			statActive++
			if !a.LastRefreshedAt.IsZero() && now.Sub(a.LastRefreshedAt) <= codexRefreshOKWindow {
				statRefreshOK++
			}
		}
		if a.Status == coreauth.StatusError {
			statError++
		}

		// Skip accounts that are disabled or quota-exceeded.
		if a.Disabled || a.Quota.Exceeded {
			continue
		}

		// Only inspect accounts in error state with a last error.
		if a.Status != coreauth.StatusError || a.LastError == nil {
			// If this account was previously counted, it has recovered.
			if prev, ok := invalidCounts[id]; ok && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, email)
				delete(invalidCounts, id)
				recovered++
			}
			continue
		}

		// Check if the error message matches any permanent error pattern.
		reason := matchPermanentError(a.LastError.Message)
		if reason == "" {
			// Error present but not a permanent pattern — reset if previously counted.
			if prev, ok := invalidCounts[id]; ok && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, email)
				delete(invalidCounts, id)
				recovered++
			}
			continue
		}

		// Increment consecutive invalid count.
		invalidCounts[id]++
		count := invalidCounts[id]
		_, email := a.AccountInfo()

		if count >= codexCleanupThreshold {
			// Auto-delete.
			log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s", id, email, codexCleanupThreshold, reason)
			h.performCodexDelete(ctx, a)
			delete(invalidCounts, id)
			autoDeleted++
		} else {
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", id, email, count, codexCleanupThreshold, reason)
			if count == 1 {
				newInvalid++
			} else {
				knownInvalid++
			}
		}
	}

	// Clean up counters for IDs that disappeared (e.g. manually deleted).
	for id := range invalidCounts {
		if _, ok := seenIDs[id]; !ok {
			delete(invalidCounts, id)
		}
	}

	// Update lifetime stats.
	lifetimeMu.Lock()
	lifetimeRounds++
	lifetimeTotalDeleted += autoDeleted
	lifetimeTotalRecover += recovered
	rounds := lifetimeRounds
	totalDel := lifetimeTotalDeleted
	totalRec := lifetimeTotalRecover
	lifetimeMu.Unlock()

	totalInvalid := newInvalid + knownInvalid
	if totalInvalid > 0 || autoDeleted > 0 || recovered > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", totalInvalid, newInvalid, knownInvalid, autoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d",
		len(codexAuths), statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d",
		rounds, totalDel, totalRec)
}

// performCodexDelete removes the auth file from disk, deletes the token record,
// and disables the auth entry in the manager.
func (h *Handler) performCodexDelete(ctx context.Context, a *coreauth.Auth) {
	if a == nil {
		return
	}

	// Remove the auth file from disk.
	if a.FileName != "" {
		filePath := a.FileName
		if !filepath.IsAbs(filePath) && h.cfg != nil && h.cfg.AuthDir != "" {
			filePath = filepath.Join(h.cfg.AuthDir, filePath)
		}
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			log.Warnf("codex cleanup: failed to remove file %s: %v", filePath, err)
		}
	}

	// Delete the token record from the store.
	if a.FileName != "" {
		if err := h.deleteTokenRecord(ctx, a.FileName); err != nil {
			log.Warnf("codex cleanup: failed to delete token record for %s: %v", a.ID, err)
		}
	}

	// Disable the auth entry in the manager.
	h.disableAuth(ctx, a.ID)
}

// matchPermanentError checks if msg matches any permanent error pattern.
// Returns the matched reason string, or empty if no match.
func matchPermanentError(msg string) string {
	if msg == "" {
		return ""
	}
	lower := strings.ToLower(msg)
	for _, parts := range permanentErrorPatterns {
		matched := true
		for _, p := range parts {
			if !strings.Contains(lower, strings.ToLower(p)) {
				matched = false
				break
			}
		}
		if matched {
			return msg
		}
	}
	return ""
}
