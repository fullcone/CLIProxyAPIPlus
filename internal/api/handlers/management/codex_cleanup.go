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

	// invalidCounts tracks consecutive permanent-error detections per auth ID.
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
	if h.authManager == nil {
		return
	}

	lifetimeRounds++

	allAuths := h.authManager.List()

	// Filter codex accounts.
	var codexAuths []*coreauth.Auth
	for _, a := range allAuths {
		if strings.ToLower(a.Provider) == "codex" {
			codexAuths = append(codexAuths, a)
		}
	}

	log.Debugf("codex cleanup: scanning %d codex accounts", len(codexAuths))

	// Per-round statistics.
	var (
		statTotal            = len(codexAuths)
		statActive           int
		statRefreshOK        int
		statError            int
		statQuotaExceeded    int
		statDisabled         int
		statDisabledCleaned  int
		statAutoDeleted      int
		statNewInvalid       int
		statKnownInvalid     int
	)

	// Track which IDs are still seen this round.
	seenIDs := make(map[string]struct{}, len(codexAuths))

	now := time.Now()

	for _, auth := range codexAuths {
		seenIDs[auth.ID] = struct{}{}

		// Count status categories.
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
			filePath := fileName
			if !filepath.IsAbs(filePath) {
				filePath = filepath.Join(h.cfg.AuthDir, fileName)
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
			// For NotExist: silently skip, also still try deleteTokenRecord for consistency
			if err != nil && os.IsNotExist(err) {
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
			// Account is healthy or not in error state — reset counter if it was tracked.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				_, email := auth.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// --- Check permanent error patterns ---
		msg := strings.ToLower(auth.LastError.Message)
		permanent := false
		for _, pair := range permanentErrorPatterns {
			if strings.Contains(msg, pair[0]) && strings.Contains(msg, pair[1]) {
				permanent = true
				break
			}
		}
		if !permanent {
			for _, pat := range permanentErrorSingle {
				if strings.Contains(msg, pat) {
					permanent = true
					break
				}
			}
		}

		if !permanent {
			// Not a permanent error — reset counter if tracked.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				_, email := auth.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// Increment consecutive count.
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]
		_, email := auth.AccountInfo()

		if count < codexCleanupThreshold {
			if count == 1 {
				statNewInvalid++
			} else {
				statKnownInvalid++
			}
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", auth.ID, email, count, codexCleanupThreshold, auth.LastError.Message)
			continue
		}

		// count >= threshold: known invalid that will be deleted this round.
		statKnownInvalid++

		// --- Auto-delete ---
		fileName := auth.FileName
		if !filepath.IsAbs(fileName) {
			fileName = filepath.Join(h.cfg.AuthDir, auth.FileName)
		}
		_ = os.Remove(fileName)
		_ = h.deleteTokenRecord(ctx, auth.FileName)
		h.disableAuth(ctx, auth.ID)
		delete(invalidCounts, auth.ID)

		statAutoDeleted++
		lifetimeTotalAutoDeleted++
		log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s", auth.ID, email, codexCleanupThreshold, auth.LastError.Message)
	}

	// Clean up invalidCounts for IDs no longer present.
	for id, prev := range invalidCounts {
		if _, ok := seenIDs[id]; !ok {
			if prev > 0 {
				lifetimeTotalRecovered++
			}
			delete(invalidCounts, id)
		}
	}

	lifetimeTotalDisabledCleaned += statDisabledCleaned

	// Summary: changes log.
	totalPermanent := statNewInvalid + statKnownInvalid
	if totalPermanent > 0 || statAutoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", totalPermanent, statNewInvalid, statKnownInvalid, statAutoDeleted)
	}

	// Summary: always output.
	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		statTotal, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		lifetimeRounds, lifetimeTotalAutoDeleted, lifetimeTotalRecovered, lifetimeTotalDisabledCleaned)
}
