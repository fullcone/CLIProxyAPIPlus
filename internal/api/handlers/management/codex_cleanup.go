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
var permanentErrorPatterns = []struct {
	parts []string
}{
	{[]string{"token refresh failed", "invalid_grant"}},
	{[]string{"token refresh failed", "status 403"}},
	{[]string{"token refresh failed", "status 401"}},
	{[]string{"token has been invalidated"}},
	{[]string{"token is expired"}},
	{[]string{"account has been deactivated"}},
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

	invalidCounts := make(map[string]int) // auth ID -> consecutive invalid count

	ticker := time.NewTicker(1 * time.Minute)
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

	// Per-round statistics.
	var (
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

	now := time.Now()
	seenIDs := make(map[string]struct{}, len(codexAuths))

	for _, auth := range codexAuths {
		seenIDs[auth.ID] = struct{}{}

		// Count status categories.
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
				email := h.codexEmail(auth)
				log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record", auth.ID, email)
				_ = h.deleteTokenRecord(ctx, fileName)
			} else if !os.IsNotExist(err) {
				log.Warnf("codex cleanup: failed to remove file for disabled account %s: %v", auth.ID, err)
			}
			// For NotExist: silently skip, also try deleteTokenRecord for consistency.
			if err != nil && os.IsNotExist(err) {
				_ = h.deleteTokenRecord(ctx, fileName)
			}
			continue
		}

		// --- Skip quota exceeded ---
		if auth.Quota.Exceeded {
			continue
		}

		// --- Only look at error status with a last error ---
		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			// Account is healthy or no error info — reset counter if previously tracked.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				email := h.codexEmail(auth)
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				lifetimeTotalRecovered++
				delete(invalidCounts, auth.ID)
			}
			continue
		}

		// --- Check permanent error patterns ---
		msg := strings.ToLower(auth.LastError.Message)
		reason := ""
		permanent := false
		for _, pat := range permanentErrorPatterns {
			matched := true
			for _, part := range pat.parts {
				if !strings.Contains(msg, part) {
					matched = false
					break
				}
			}
			if matched {
				reason = auth.LastError.Message
				permanent = true
				break
			}
		}

		if !permanent {
			// Not a permanent error — reset counter if previously tracked.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				email := h.codexEmail(auth)
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				lifetimeTotalRecovered++
				delete(invalidCounts, auth.ID)
			}
			continue
		}

		// Increment consecutive invalid count.
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]
		email := h.codexEmail(auth)

		log.Debugf("codex cleanup: %s (%s) invalid count %d/1 — reason: %s", auth.ID, email, count, reason)

		if count >= 1 {
			if count == 1 {
				newInvalid++
			} else {
				knownInvalid++
			}

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

			log.Warnf("codex cleanup: auto-deleted %s (%s) after 1 check — reason: %s", auth.ID, email, reason)
			statAutoDeleted++
			lifetimeTotalAutoDeleted++
			delete(invalidCounts, auth.ID)
		} else {
			newInvalid++
		}
	}

	// Purge counters for IDs no longer present.
	for id, prev := range invalidCounts {
		if _, exists := seenIDs[id]; !exists {
			if prev > 0 {
				lifetimeTotalRecovered++
			}
			delete(invalidCounts, id)
		}
	}

	lifetimeTotalDisabledCleaned += statDisabledCleaned

	totalInvalid := newInvalid + knownInvalid
	if totalInvalid > 0 || statAutoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted",
			totalInvalid, newInvalid, knownInvalid, statAutoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		len(codexAuths), statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		lifetimeRounds, lifetimeTotalAutoDeleted, lifetimeTotalRecovered, lifetimeTotalDisabledCleaned)
}

func (h *Handler) codexEmail(auth *coreauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if email, ok := auth.Metadata["email"].(string); ok {
		return strings.TrimSpace(email)
	}
	return ""
}
