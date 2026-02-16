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

// codexInvalidCount tracks consecutive permanent-failure detections per auth ID.
var codexInvalidCount = make(map[string]int)

// codexCleanupMu guards codexInvalidCount and prevents overlapping scans.
var codexCleanupMu sync.Mutex

// lifetime statistics (package-level, never reset)
var (
	codexLifetimeRounds       int
	codexLifetimeAutoDeleted  int
	codexLifetimeRecovered    int
)

const (
	codexCleanupInitialDelay = 30 * time.Second
	codexCleanupInterval     = 5 * time.Minute
	codexCleanupThreshold    = 3
	codexRecentRefreshWindow = 10 * time.Minute
)

// isPermanentlyInvalid checks whether the error message indicates a permanently
// revoked / invalidated Codex OAuth token.
func isPermanentlyInvalid(msg string) bool {
	lower := strings.ToLower(msg)

	if strings.Contains(lower, "token has been invalidated") {
		return true
	}
	if strings.Contains(lower, "token is expired") {
		return true
	}
	if strings.Contains(lower, "token refresh failed") {
		if strings.Contains(lower, "invalid_grant") {
			return true
		}
		if strings.Contains(lower, "status 403") {
			return true
		}
		if strings.Contains(lower, "status 401") {
			return true
		}
	}
	return false
}

// StartCodexCleanup launches the background goroutine that periodically scans
// Codex accounts and auto-deletes permanently invalid ones.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	go func() {
		select {
		case <-time.After(codexCleanupInitialDelay):
		case <-ctx.Done():
			return
		}

		h.runCodexCleanup(ctx)

		ticker := time.NewTicker(codexCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.runCodexCleanup(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// runCodexCleanup performs a single scan round.
func (h *Handler) runCodexCleanup(ctx context.Context) {
	if !codexCleanupMu.TryLock() {
		return
	}
	defer codexCleanupMu.Unlock()

	if h == nil || h.authManager == nil {
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

	// Summary counters.
	var (
		totalCount        int
		activeCount       int
		refreshOKCount    int
		errorCount        int
		quotaExceededCount int
		disabledCount     int
	)

	// Round counters.
	var (
		permanentInvalidNew   int
		permanentInvalidKnown int
		autoDeletedThisRound  int
		recoveredThisRound    int
	)

	// Track which IDs are still permanently invalid this round.
	seenInvalid := make(map[string]bool)

	for _, a := range codexAuths {
		totalCount++

		if a.Disabled {
			disabledCount++
			continue
		}
		if a.Status == coreauth.StatusActive {
			activeCount++
			if !a.LastRefreshedAt.IsZero() && now.Sub(a.LastRefreshedAt) <= codexRecentRefreshWindow {
				refreshOKCount++
			}
		}
		if a.Status == coreauth.StatusError {
			errorCount++
		}
		if a.Quota.Exceeded {
			quotaExceededCount++
		}

		// Only inspect accounts that are in error state with a last error.
		if a.Status != coreauth.StatusError || a.LastError == nil {
			// If this account was previously tracked as invalid, it recovered.
			if prev, exists := codexInvalidCount[a.ID]; exists && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", a.ID, email)
				delete(codexInvalidCount, a.ID)
				recoveredThisRound++
			}
			continue
		}

		// Skip quota-exceeded accounts — they are only temporarily unavailable.
		if a.Quota.Exceeded {
			if prev, exists := codexInvalidCount[a.ID]; exists && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", a.ID, email)
				delete(codexInvalidCount, a.ID)
				recoveredThisRound++
			}
			continue
		}

		errMsg := a.LastError.Message
		if !isPermanentlyInvalid(errMsg) {
			// Error changed to something non-permanent — reset.
			if prev, exists := codexInvalidCount[a.ID]; exists && prev > 0 {
				_, email := a.AccountInfo()
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", a.ID, email)
				delete(codexInvalidCount, a.ID)
				recoveredThisRound++
			}
			continue
		}

		// Permanently invalid — increment counter.
		seenInvalid[a.ID] = true
		codexInvalidCount[a.ID]++
		count := codexInvalidCount[a.ID]
		_, email := a.AccountInfo()

		if count >= codexCleanupThreshold {
			// Auto-delete.
			reason := errMsg
			if len(reason) > 200 {
				reason = reason[:200] + "..."
			}

			// 1. Remove auth file from disk.
			if a.FileName != "" {
				filePath := a.FileName
				if !filepath.IsAbs(filePath) && h.cfg != nil && h.cfg.AuthDir != "" {
					filePath = filepath.Join(h.cfg.AuthDir, filePath)
				}
				if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
					log.Warnf("codex cleanup: failed to remove file %s: %v", filePath, err)
				}
			}

			// 2. Delete token store record.
			if a.FileName != "" {
				_ = h.deleteTokenRecord(ctx, a.FileName)
			}

			// 3. Disable auth in manager.
			h.disableAuth(ctx, a.ID)

			log.Warnf("codex cleanup: auto-deleted %s (%s) after %d consecutive checks — reason: %s",
				a.ID, email, codexCleanupThreshold, reason)

			delete(codexInvalidCount, a.ID)
			autoDeletedThisRound++
		} else {
			if count == 1 {
				permanentInvalidNew++
			} else {
				permanentInvalidKnown++
			}
			log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s",
				a.ID, email, count, codexCleanupThreshold, errMsg)
		}
	}

	// Clean up stale entries for IDs no longer in the codex list.
	for id := range codexInvalidCount {
		if !seenInvalid[id] {
			// Already handled above via recovery logic, but just in case.
			delete(codexInvalidCount, id)
		}
	}

	// Update lifetime stats.
	codexLifetimeRounds++
	codexLifetimeAutoDeleted += autoDeletedThisRound
	codexLifetimeRecovered += recoveredThisRound

	// Log round results (only when there were changes).
	totalPermanentInvalid := permanentInvalidNew + permanentInvalidKnown
	if totalPermanentInvalid > 0 || autoDeletedThisRound > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted",
			totalPermanentInvalid, permanentInvalidNew, permanentInvalidKnown, autoDeletedThisRound)
	}

	// Always log summary.
	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d",
		totalCount, activeCount, refreshOKCount, errorCount, quotaExceededCount, disabledCount)

	// Always log lifetime stats.
	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d",
		codexLifetimeRounds, codexLifetimeAutoDeleted, codexLifetimeRecovered)
}
