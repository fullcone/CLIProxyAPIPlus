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
// Each entry is a pair: both substrings must appear in LastError.Message.
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
)

// Package-level lifetime counters.
var (
	lifetimeRounds              int
	lifetimeTotalAutoDeleted    int
	lifetimeTotalRecovered      int
	lifetimeTotalDisabledCleaned int
)

var codexCleanupOnce sync.Once

// StartCodexCleanup launches the background Codex account cleanup goroutine.
// It is safe to call multiple times; only the first invocation starts the loop.
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

	// invalidCounts tracks consecutive permanent-error detections per auth ID.
	invalidCounts := make(map[string]int)

	// Run first scan immediately, then on ticker.
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
		statActive          int
		statRefreshOK       int
		statError           int
		statQuotaExceeded   int
		statDisabled        int
		statDisabledCleaned int
	)

	// Track which IDs are still permanently invalid this round.
	currentInvalid := make(map[string]bool)
	var autoDeleted int
	var newInvalid, knownInvalid int

	now := time.Now()

	for _, auth := range codexAuths {
		_, email := auth.AccountInfo()

		// --- Disabled accounts: clean residual files ---
		if auth.Disabled {
			statDisabled++
			cleaned := false
			if auth.FileName != "" {
				full := filepath.Join(h.cfg.AuthDir, filepath.Base(auth.FileName))
				if err := os.Remove(full); err == nil {
					cleaned = true
				}
			}
			if err := h.deleteTokenRecord(ctx, auth.FileName); err == nil {
				cleaned = true
			}
			if cleaned {
				statDisabledCleaned++
				lifetimeTotalDisabledCleaned++
				log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record", auth.ID, email)
			}
			continue
		}

		// Count active.
		if auth.Status == coreauth.StatusActive {
			statActive++
			if !auth.LastRefreshedAt.IsZero() && now.Sub(auth.LastRefreshedAt) <= 10*time.Minute {
				statRefreshOK++
			}
		}

		// Skip quota-exceeded.
		if auth.Quota.Exceeded {
			statQuotaExceeded++
			continue
		}

		// Only inspect error-state accounts.
		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			// If this account was previously tracked, it recovered.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		statError++

		msg := strings.ToLower(auth.LastError.Message)
		if !isPermanentCodexError(msg) {
			// Was tracked before but no longer matches — recovered.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// Permanent error detected — increment counter.
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]
		currentInvalid[auth.ID] = true

		if count >= codexCleanupThreshold {
			// Auto-delete.
			reason := auth.LastError.Message
			if auth.FileName != "" {
				full := filepath.Join(h.cfg.AuthDir, filepath.Base(auth.FileName))
				_ = os.Remove(full)
			}
			_ = h.deleteTokenRecord(ctx, auth.FileName)
			h.disableAuth(ctx, auth.ID)
			delete(invalidCounts, auth.ID)
			autoDeleted++
			lifetimeTotalAutoDeleted++
			log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s", auth.ID, email, codexCleanupThreshold, reason)
		} else {
			if count == 1 {
				newInvalid++
			} else {
				knownInvalid++
			}
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", auth.ID, email, count, codexCleanupThreshold, auth.LastError.Message)
		}
	}

	// Purge stale entries for IDs no longer in the codex list.
	for id, cnt := range invalidCounts {
		if cnt > 0 && !currentInvalid[id] {
			// Account disappeared from list (already deleted externally or provider changed).
			delete(invalidCounts, id)
		}
	}

	permanentlyInvalid := newInvalid + knownInvalid
	if permanentlyInvalid > 0 || autoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", permanentlyInvalid, newInvalid, knownInvalid, autoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		total, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		lifetimeRounds, lifetimeTotalAutoDeleted, lifetimeTotalRecovered, lifetimeTotalDisabledCleaned)
}

// isPermanentCodexError checks whether the lowercased error message matches
// any of the known permanent failure patterns.
func isPermanentCodexError(msg string) bool {
	for _, pat := range permanentErrorPatterns {
		if pat[1] == "" {
			// Single-substring match.
			if strings.Contains(msg, pat[0]) {
				return true
			}
		} else {
			if strings.Contains(msg, pat[0]) && strings.Contains(msg, pat[1]) {
				return true
			}
		}
	}
	return false
}
