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
	codexCleanupThreshold    = 3
)

// isPermanentlyInvalidCodex checks whether the error message indicates a
// permanently invalid Codex OAuth token. It returns true and a short reason
// string when the token cannot be recovered by retrying.
func isPermanentlyInvalidCodex(msg string) (bool, string) {
	lower := strings.ToLower(msg)

	if strings.Contains(lower, "token has been invalidated") {
		return true, "token has been invalidated"
	}
	if strings.Contains(lower, "token is expired") {
		return true, "token is expired"
	}
	if strings.Contains(lower, "token refresh failed") {
		if strings.Contains(lower, "invalid_grant") {
			return true, "token refresh failed: invalid_grant"
		}
		if strings.Contains(lower, "status 403") {
			return true, "token refresh failed: status 403"
		}
		if strings.Contains(lower, "status 401") {
			return true, "token refresh failed: status 401"
		}
	}
	return false, ""
}

// StartCodexCleanup launches a background goroutine that periodically scans
// Codex OAuth accounts and auto-deletes those that are permanently invalid
// after codexCleanupThreshold consecutive confirmations.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	go h.runCodexCleanupLoop(ctx)
}

func (h *Handler) runCodexCleanupLoop(ctx context.Context) {
	// Wait for auth manager to finish loading.
	select {
	case <-ctx.Done():
		return
	case <-time.After(codexCleanupInitialDelay):
	}

	var running sync.Mutex
	codexInvalidCount := make(map[string]int)

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()

	// Run first scan immediately after initial delay, then on ticker.
	h.codexCleanupScan(ctx, codexInvalidCount, &running)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.codexCleanupScan(ctx, codexInvalidCount, &running)
		}
	}
}

func (h *Handler) codexCleanupScan(ctx context.Context, codexInvalidCount map[string]int, running *sync.Mutex) {
	if !running.TryLock() {
		return
	}
	defer running.Unlock()

	if h.authManager == nil {
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

	// Track which IDs are still seen as invalid this round.
	seenInvalid := make(map[string]bool)

	var (
		newInvalid   int
		knownInvalid int
		autoDeleted  int
	)

	for _, a := range codexAuths {
		id := a.ID
		if id == "" {
			id = a.FileName
		}
		if id == "" {
			continue
		}

		// Skip disabled accounts.
		if a.Disabled {
			continue
		}

		// Skip accounts not in error state.
		if a.Status != coreauth.StatusError || a.LastError == nil {
			// If this account was previously tracked, it recovered.
			if prev, ok := codexInvalidCount[id]; ok && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, email)
				delete(codexInvalidCount, id)
			}
			continue
		}

		// Skip quota-exceeded accounts (temporary).
		if a.Quota.Exceeded {
			if prev, ok := codexInvalidCount[id]; ok && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, email)
				delete(codexInvalidCount, id)
			}
			continue
		}

		invalid, reason := isPermanentlyInvalidCodex(a.LastError.Message)
		if !invalid {
			// Error changed to something non-permanent — reset.
			if prev, ok := codexInvalidCount[id]; ok && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, email)
				delete(codexInvalidCount, id)
			}
			continue
		}

		seenInvalid[id] = true
		codexInvalidCount[id]++
		count := codexInvalidCount[id]
		_, email := a.AccountInfo()

		if count >= codexCleanupThreshold {
			// Auto-delete.
			h.doCodexAutoDelete(ctx, a, id, email, reason)
			delete(codexInvalidCount, id)
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

	// Clean up counters for IDs that are no longer in the invalid set
	// (e.g. account was deleted externally or provider changed).
	for id := range codexInvalidCount {
		if !seenInvalid[id] {
			delete(codexInvalidCount, id)
		}
	}

	totalInvalid := newInvalid + knownInvalid
	if totalInvalid > 0 || autoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", totalInvalid, newInvalid, knownInvalid, autoDeleted)
	}
}

func (h *Handler) doCodexAutoDelete(ctx context.Context, a *coreauth.Auth, id, email, reason string) {
	// 1. Remove the auth file from disk.
	if a.FileName != "" {
		filePath := a.FileName
		if h.cfg != nil && h.cfg.AuthDir != "" && !filepath.IsAbs(filePath) {
			filePath = filepath.Join(h.cfg.AuthDir, filePath)
		}
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			log.Warnf("codex cleanup: failed to remove file %s: %v", filePath, err)
		}
	}

	// 2. Delete the token store record.
	path := a.FileName
	if path == "" {
		path = id
	}
	if err := h.deleteTokenRecord(ctx, path); err != nil {
		log.Debugf("codex cleanup: deleteTokenRecord for %s: %v", id, err)
	}

	// 3. Mark auth as disabled in the manager.
	h.disableAuth(ctx, id)

	log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s", id, email, codexCleanupThreshold, reason)
}
