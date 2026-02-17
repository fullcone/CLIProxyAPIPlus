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
	codexRefreshOKWindow     = 10 * time.Minute
)

// Lifetime statistics (package-level).
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

	// In-memory consecutive-failure counters keyed by auth ID.
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

	// Track which IDs are still present this round.
	seenIDs := make(map[string]struct{}, total)

	now := time.Now()

	for _, auth := range codexAuths {
		seenIDs[auth.ID] = struct{}{}

		// Gather summary stats.
		if auth.Status == coreauth.StatusActive {
			statActive++
			if !auth.LastRefreshedAt.IsZero() && now.Sub(auth.LastRefreshedAt) <= codexRefreshOKWindow {
				statRefreshOK++
			}
		}
		if auth.Status == coreauth.StatusError {
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
			fileName := strings.TrimSpace(auth.FileName)
			if fileName == "" {
				fileName = strings.TrimSpace(auth.ID)
			}
			if fileName == "" {
				continue
			}
			filePath := fileName
			if !filepath.IsAbs(filePath) {
				filePath = filepath.Join(h.cfg.AuthDir, filePath)
			}

			err := os.Remove(filePath)
			if err == nil {
				statDisabledCleaned++
				_, email := auth.AccountInfo()
				log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record", auth.ID, email)
				_ = h.deleteTokenRecord(ctx, fileName)
			} else if !os.IsNotExist(err) {
				log.Warnf("codex cleanup: failed to remove file for disabled account %s: %v", auth.ID, err)
			}
			// For NotExist: silently skip, also try to clean token record.
			if err != nil && os.IsNotExist(err) {
				_ = h.deleteTokenRecord(ctx, fileName)
			}
			continue
		}

		// --- Skip quota-exceeded accounts ---
		if auth.Quota.Exceeded {
			continue
		}

		// --- Only look at error-state accounts with a last error ---
		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			// Account is healthy or has no error info — reset counter if it was tracked.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				_, email := auth.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// --- Check permanent invalidity ---
		msg := auth.LastError.Message
		if !isPermanentlyInvalid(msg) {
			// Not permanently invalid — reset counter if tracked.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				_, email := auth.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// Permanently invalid — increment counter.
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]
		_, email := auth.AccountInfo()

		if count >= codexCleanupThreshold {
			// Auto-delete.
			fileName := strings.TrimSpace(auth.FileName)
			if fileName == "" {
				fileName = strings.TrimSpace(auth.ID)
			}
			filePath := fileName
			if fileName != "" && !filepath.IsAbs(filePath) {
				filePath = filepath.Join(h.cfg.AuthDir, filePath)
			}
			if filePath != "" {
				_ = os.Remove(filePath)
			}
			if fileName != "" {
				_ = h.deleteTokenRecord(ctx, fileName)
			}
			h.disableAuth(ctx, auth.ID)
			delete(invalidCounts, auth.ID)
			autoDeleted++
			lifetimeTotalAutoDeleted++
			log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s", auth.ID, email, codexCleanupThreshold, msg)
		} else {
			if count == 1 {
				newInvalid++
			} else {
				knownInvalid++
			}
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", auth.ID, email, count, codexCleanupThreshold, msg)
		}
	}

	// Clean up counters for accounts that no longer exist.
	for id := range invalidCounts {
		if _, ok := seenIDs[id]; !ok {
			delete(invalidCounts, id)
		}
	}

	lifetimeTotalDisabledCleaned += statDisabledCleaned

	// Per-round change summary (only when something happened).
	permanentlyInvalid := newInvalid + knownInvalid
	if permanentlyInvalid > 0 || autoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", permanentlyInvalid, newInvalid, knownInvalid, autoDeleted)
	}

	// Per-round summary (always).
	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		total, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	// Lifetime summary (always).
	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		lifetimeRounds, lifetimeTotalAutoDeleted, lifetimeTotalRecovered, lifetimeTotalDisabledCleaned)
}

// isPermanentlyInvalid checks whether the error message matches any known permanent failure pattern.
func isPermanentlyInvalid(msg string) bool {
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
