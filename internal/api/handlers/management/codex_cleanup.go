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

const (
	codexCleanupInitialDelay = 30 * time.Second
	codexCleanupInterval     = 5 * time.Minute
	codexCleanupThreshold    = 3 // consecutive checks before auto-delete
)

// isPermanentlyInvalid checks whether the LastError message indicates a
// permanently revoked / expired Codex OAuth token.
func isPermanentlyInvalid(msg string) (bool, string) {
	lower := strings.ToLower(msg)

	switch {
	case strings.Contains(lower, "token refresh failed") && strings.Contains(lower, "invalid_grant"):
		return true, "token refresh failed: invalid_grant"
	case strings.Contains(lower, "token refresh failed") && strings.Contains(lower, "status 403"):
		return true, "token refresh failed: status 403"
	case strings.Contains(lower, "token refresh failed") && strings.Contains(lower, "status 401"):
		return true, "token refresh failed: status 401"
	case strings.Contains(lower, "token has been invalidated"):
		return true, "token has been invalidated"
	case strings.Contains(lower, "token is expired"):
		return true, "token is expired"
	}
	return false, ""
}

// StartCodexCleanup launches the background goroutine that periodically scans
// Codex OAuth accounts and auto-deletes permanently invalid ones.
// It is safe to call multiple times; only the first invocation starts the loop.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	var once sync.Once
	once.Do(func() {
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

	codexInvalidCount := make(map[string]int)

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()

	// Run immediately after initial delay, then on every tick.
	h.codexCleanupRound(ctx, codexInvalidCount)

	for {
		select {
		case <-ticker.C:
			h.codexCleanupRound(ctx, codexInvalidCount)
		case <-ctx.Done():
			return
		}
	}
}

func (h *Handler) codexCleanupRound(ctx context.Context, codexInvalidCount map[string]int) {
	if h == nil || h.authManager == nil {
		return
	}

	allAuths := h.authManager.List()

	// Collect codex accounts only.
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

	// Track which IDs are still seen this round (for counter cleanup).
	seen := make(map[string]struct{}, len(codexAuths))

	var (
		newInvalid   int
		knownInvalid int
		autoDeleted  int
	)

	for _, a := range codexAuths {
		id := a.ID
		seen[id] = struct{}{}

		// Skip disabled accounts.
		if a.Disabled {
			continue
		}

		// Skip quota-exceeded accounts (temporary).
		if a.Quota.Exceeded {
			// If it was previously counted, reset.
			if codexInvalidCount[id] > 0 {
				log.Infof("codex cleanup: %s (%s) recovered (quota-exceeded, not permanent), resetting counter", id, h.codexAccountEmail(a))
				delete(codexInvalidCount, id)
			}
			continue
		}

		// Only look at error-state accounts with a LastError.
		if a.Status != coreauth.StatusError || a.LastError == nil {
			if codexInvalidCount[id] > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, h.codexAccountEmail(a))
				delete(codexInvalidCount, id)
			}
			continue
		}

		invalid, reason := isPermanentlyInvalid(a.LastError.Message)
		if !invalid {
			if codexInvalidCount[id] > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, h.codexAccountEmail(a))
				delete(codexInvalidCount, id)
			}
			continue
		}

		codexInvalidCount[id]++
		count := codexInvalidCount[id]

		if count >= codexCleanupThreshold {
			// Auto-delete.
			h.codexAutoDelete(ctx, a, reason)
			delete(codexInvalidCount, id)
			autoDeleted++
		} else {
			if count == 1 {
				newInvalid++
			} else {
				knownInvalid++
			}
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s",
				id, h.codexAccountEmail(a), count, codexCleanupThreshold, reason)
		}
	}

	// Purge counters for IDs no longer present.
	for id := range codexInvalidCount {
		if _, ok := seen[id]; !ok {
			delete(codexInvalidCount, id)
		}
	}

	totalInvalid := newInvalid + knownInvalid
	if totalInvalid > 0 || autoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted",
			totalInvalid, newInvalid, knownInvalid, autoDeleted)
	}
}

func (h *Handler) codexAutoDelete(ctx context.Context, a *coreauth.Auth, reason string) {
	email := h.codexAccountEmail(a)

	// 1. Remove the auth file from disk.
	if a.FileName != "" {
		filePath := a.FileName
		if h.cfg != nil && h.cfg.AuthDir != "" && !filepath.IsAbs(filePath) {
			filePath = filepath.Join(h.cfg.AuthDir, filePath)
		}
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			log.Warnf("codex cleanup: failed to remove auth file %s: %v", filePath, err)
		}
	}

	// 2. Delete token store record.
	if a.FileName != "" {
		if err := h.deleteTokenRecord(ctx, a.FileName); err != nil {
			log.Warnf("codex cleanup: failed to delete token record for %s: %v", a.ID, err)
		}
	}

	// 3. Mark as disabled in auth manager.
	h.disableAuth(ctx, a.ID)

	log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s",
		a.ID, email, codexCleanupThreshold, reason)
}

func (h *Handler) codexAccountEmail(a *coreauth.Auth) string {
	if a == nil {
		return ""
	}
	_, info := a.AccountInfo()
	if info != "" {
		return info
	}
	return a.ID
}
