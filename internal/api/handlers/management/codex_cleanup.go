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

const (
	codexCleanupInitialDelay = 30 * time.Second
	codexCleanupInterval     = 5 * time.Minute
	codexCleanupThreshold    = 3
	codexRefreshOKWindow     = 10 * time.Minute
)

// Package-level lifetime counters.
var (
	cleanupLifetimeRounds       int
	cleanupLifetimeTotalDeleted int
	cleanupLifetimeTotalRecover int
)

var codexCleanupOnce sync.Once

// StartCodexCleanup launches the background Codex cleanup loop.
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

	invalidCounts := make(map[string]int) // auth ID -> consecutive invalid count

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()

	for {
		h.runCodexCleanup(ctx, invalidCounts)

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func (h *Handler) runCodexCleanup(ctx context.Context, invalidCounts map[string]int) {
	if h == nil || h.authManager == nil {
		return
	}

	cleanupLifetimeRounds++

	allAuths := h.authManager.List()

	// Collect only codex accounts.
	var codexAuths []*coreauth.Auth
	for _, a := range allAuths {
		if strings.EqualFold(a.Provider, "codex") {
			codexAuths = append(codexAuths, a)
		}
	}

	log.Debugf("codex cleanup: scanning %d codex accounts", len(codexAuths))

	// Track IDs seen this round to prune stale entries from invalidCounts.
	seenIDs := make(map[string]struct{}, len(codexAuths))

	var (
		newInvalid   int
		knownInvalid int
		autoDeleted  int
		// summary counters
		statActive        int
		statRefreshOK     int
		statError         int
		statQuotaExceeded int
		statDisabled      int
	)

	now := time.Now()

	for _, a := range codexAuths {
		seenIDs[a.ID] = struct{}{}

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
			// If this account was previously counted, it recovered.
			if prev, ok := invalidCounts[a.ID]; ok && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", a.ID, email)
				delete(invalidCounts, a.ID)
				cleanupLifetimeTotalRecover++
			}
			continue
		}

		msg := strings.ToLower(a.LastError.Message)
		reason := a.LastError.Message
		permanent := false
		for _, pattern := range permanentErrorPatterns {
			matched := true
			for _, sub := range pattern {
				if !strings.Contains(msg, sub) {
					matched = false
					break
				}
			}
			if matched {
				permanent = true
				break
			}
		}

		if !permanent {
			// Not a permanent error — reset counter if previously tracked.
			if prev, ok := invalidCounts[a.ID]; ok && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", a.ID, email)
				delete(invalidCounts, a.ID)
				cleanupLifetimeTotalRecover++
			}
			continue
		}

		// Increment consecutive invalid count.
		prev := invalidCounts[a.ID]
		invalidCounts[a.ID] = prev + 1
		count := invalidCounts[a.ID]

		_, email := a.AccountInfo()

		if count >= codexCleanupThreshold {
			// Auto-delete.
			log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s", a.ID, email, codexCleanupThreshold, reason)

			// Remove auth file from disk.
			if a.FileName != "" {
				filePath := a.FileName
				if !filepath.IsAbs(filePath) && h.cfg != nil && h.cfg.AuthDir != "" {
					filePath = filepath.Join(h.cfg.AuthDir, filePath)
				}
				_ = os.Remove(filePath)
			}

			// Delete token record from store.
			if a.FileName != "" {
				_ = h.deleteTokenRecord(ctx, a.FileName)
			}

			// Disable in auth manager.
			h.disableAuth(ctx, a.ID)

			delete(invalidCounts, a.ID)
			autoDeleted++
			cleanupLifetimeTotalDeleted++
		} else {
			if prev == 0 {
				newInvalid++
			} else {
				knownInvalid++
			}
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", a.ID, email, count, codexCleanupThreshold, reason)
		}
	}

	// Prune stale entries for accounts that no longer exist.
	for id := range invalidCounts {
		if _, ok := seenIDs[id]; !ok {
			delete(invalidCounts, id)
		}
	}

	totalPermanent := newInvalid + knownInvalid
	if totalPermanent > 0 || autoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", totalPermanent, newInvalid, knownInvalid, autoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d",
		len(codexAuths), statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d",
		cleanupLifetimeRounds, cleanupLifetimeTotalDeleted, cleanupLifetimeTotalRecover)
}
