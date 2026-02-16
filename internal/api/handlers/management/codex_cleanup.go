package management

import (
	"context"
	"fmt"
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

// codexInvalidCount tracks consecutive permanent-failure detections per auth ID.
var (
	codexInvalidMu    sync.Mutex
	codexInvalidCount = make(map[string]int)
	codexCleanupOnce  sync.Once
)

// isPermanentCodexError checks whether the error message indicates a permanently
// invalid Codex OAuth token that will never recover.
func isPermanentCodexError(msg string) (bool, string) {
	lower := strings.ToLower(msg)

	if strings.Contains(lower, "token refresh failed") {
		switch {
		case strings.Contains(lower, "invalid_grant"):
			return true, "token refresh failed: invalid_grant"
		case strings.Contains(lower, "status 403"):
			return true, "token refresh failed: status 403"
		case strings.Contains(lower, "status 401"):
			return true, "token refresh failed: status 401"
		}
	}
	if strings.Contains(lower, "token has been invalidated") {
		return true, "token has been invalidated"
	}
	if strings.Contains(lower, "token is expired") {
		return true, "token is expired"
	}
	return false, ""
}

// StartCodexCleanup launches the background goroutine that periodically scans
// Codex accounts and auto-deletes permanently invalid ones. Safe to call
// multiple times; only the first invocation starts the loop.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	if h == nil {
		return
	}
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

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()

	h.runCodexCleanup(ctx)
	for {
		select {
		case <-ticker.C:
			h.runCodexCleanup(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (h *Handler) runCodexCleanup(ctx context.Context) {
	if h == nil || h.authManager == nil {
		return
	}

	allAuths := h.authManager.List()

	// Collect codex accounts to scan.
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

	codexInvalidMu.Lock()
	defer codexInvalidMu.Unlock()

	var (
		newInvalid   int
		knownInvalid int
		autoDeleted  int
	)

	// Track which IDs are still seen this round so we can detect recoveries.
	seenIDs := make(map[string]struct{}, len(codexAuths))

	for _, a := range codexAuths {
		id := a.ID
		seenIDs[id] = struct{}{}

		// Skip disabled accounts.
		if a.Disabled {
			delete(codexInvalidCount, id)
			continue
		}

		// Skip quota-exceeded accounts (transient).
		if a.Quota.Exceeded {
			if codexInvalidCount[id] > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, email)
			}
			delete(codexInvalidCount, id)
			continue
		}

		// Only inspect accounts in error state with a recorded error.
		if a.Status != coreauth.StatusError || a.LastError == nil {
			if codexInvalidCount[id] > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, email)
			}
			delete(codexInvalidCount, id)
			continue
		}

		permanent, reason := isPermanentCodexError(a.LastError.Message)
		if !permanent {
			if codexInvalidCount[id] > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, email)
			}
			delete(codexInvalidCount, id)
			continue
		}

		codexInvalidCount[id]++
		count := codexInvalidCount[id]
		_, email := a.AccountInfo()

		if count >= codexCleanupThreshold {
			// Auto-delete.
			h.autoDeleteCodexAuth(ctx, a, reason)
			delete(codexInvalidCount, id)
			autoDeleted++
			log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s", id, email, codexCleanupThreshold, reason)
		} else {
			if count == 1 {
				newInvalid++
			} else {
				knownInvalid++
			}
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", id, email, count, codexCleanupThreshold, reason)
		}
	}

	// Clean up counters for IDs that disappeared (e.g. manually deleted).
	for id := range codexInvalidCount {
		if _, ok := seenIDs[id]; !ok {
			delete(codexInvalidCount, id)
		}
	}

	totalInvalid := newInvalid + knownInvalid
	if totalInvalid > 0 || autoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", totalInvalid, newInvalid, knownInvalid, autoDeleted)
	}
}

// autoDeleteCodexAuth removes a permanently invalid Codex auth: deletes the
// file on disk, removes the token store record, and disables the auth entry.
func (h *Handler) autoDeleteCodexAuth(ctx context.Context, a *coreauth.Auth, reason string) {
	if a == nil {
		return
	}

	// Remove auth file from disk.
	fileName := strings.TrimSpace(a.FileName)
	if fileName != "" {
		authDir := ""
		if h.cfg != nil {
			authDir = h.cfg.AuthDir
		}
		fullPath := fileName
		if authDir != "" && !filepath.IsAbs(fileName) {
			fullPath = filepath.Join(authDir, fileName)
		}
		if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
			_, email := a.AccountInfo()
			log.Warnf("codex cleanup: failed to remove file for %s (%s): %v", a.ID, email, err)
		}
	}

	// Delete token store record.
	if fileName != "" {
		if err := h.deleteTokenRecord(ctx, fileName); err != nil {
			_, email := a.AccountInfo()
			log.Warnf("codex cleanup: failed to delete token record for %s (%s): %v", a.ID, email, err)
		}
	}

	// Disable auth entry in manager.
	h.disableAuth(ctx, a.ID)

	// Also update status message to record the reason.
	if auth, ok := h.authManager.GetByID(a.ID); ok {
		auth.StatusMessage = fmt.Sprintf("auto-deleted by codex cleanup: %s", reason)
		auth.UpdatedAt = time.Now()
		_, _ = h.authManager.Update(ctx, auth)
	}
}
