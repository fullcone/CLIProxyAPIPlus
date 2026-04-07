package management

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// codexCleanupInitialDelay is the delay before the first cleanup scan after startup.
const codexCleanupInitialDelay = 30 * time.Second

// codexCleanupInterval is the interval between successive cleanup scans.
const codexCleanupInterval = 1 * time.Minute

// codexCleanupDeleteThreshold is the number of consecutive scan rounds an auth must
// appear as permanently failed before it is deleted.
const codexCleanupDeleteThreshold = 1

// permanentFailureKeywords are error message substrings (matched case-insensitively) that
// indicate a Codex OAuth token is permanently invalid and cannot be recovered by retrying.
var permanentFailureKeywords = []string{
	"token has been invalidated",
	"account has been deactivated",
	"token_revoked",
	"invalidated oauth token",
	"refresh_token_reused",
	"refresh token has already been used",
}

// codexCleanupStarted guards against multiple invocations of StartCodexCleanup.
// It is an instance-level field on Handler; the atomic bool here is used as a
// lightweight guard without requiring a full mutex.
func (h *Handler) codexCleanupStartedField() *atomic.Bool {
	// Lazily initialize via the existing handler mutex to keep the Handler struct
	// zero-value safe without changing its initializer.
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cleanupStarted == nil {
		h.cleanupStarted = &atomic.Bool{}
	}
	return h.cleanupStarted
}

// StartCodexCleanup launches the background cleanup goroutine for permanently
// invalid Codex OAuth accounts. It is safe to call multiple times; only the
// first invocation will start the goroutine.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	if h == nil || h.authManager == nil {
		return
	}
	started := h.codexCleanupStartedField()
	if !started.CompareAndSwap(false, true) {
		return
	}
	go h.runCodexCleanup(ctx)
}

// runCodexCleanup is the long-running cleanup loop. It waits for the initial
// delay and then scans every codexCleanupInterval.
func (h *Handler) runCodexCleanup(ctx context.Context) {
	log.Info("codex cleanup: background goroutine started, waiting for initial delay")
	select {
	case <-ctx.Done():
		return
	case <-time.After(codexCleanupInitialDelay):
	}
	log.Info("codex cleanup: initial delay elapsed, starting periodic scans")

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()

	// failCounts tracks how many consecutive scan rounds each auth ID has been
	// observed with a permanent failure keyword. When the count reaches the
	// threshold the auth is removed.
	failCounts := make(map[string]int)

	for {
		h.codexCleanupScan(ctx, failCounts)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// codexCleanupScan performs a single pass over all codex auth entries.
func (h *Handler) codexCleanupScan(ctx context.Context, failCounts map[string]int) {
	if h == nil || h.authManager == nil {
		return
	}
	auths := h.authManager.List()
	if len(auths) == 0 {
		return
	}

	var (
		statScanned         int
		statDisabledCleaned int
		statDeleted         int
		statRecovered       int
	)

	// Track which IDs are still present so we can prune stale failCounts entries.
	activeIDs := make(map[string]struct{}, len(auths))

	for _, auth := range auths {
		if auth == nil || auth.ID == "" {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
			continue
		}
		statScanned++
		activeIDs[auth.ID] = struct{}{}

		filePath := h.resolveAuthFilePath(auth)

		// --- Disabled entries: clean residual files ---
		if auth.Disabled {
			if filePath != "" {
				if err := os.Remove(filePath); err == nil {
					statDisabledCleaned++
					log.Infof("codex cleanup: removed residual file for disabled auth %s: %s", auth.ID, filePath)
				} else if !os.IsNotExist(err) {
					log.Warnf("codex cleanup: failed to remove residual file for disabled auth %s: %v", auth.ID, err)
				}
				// Always attempt token record cleanup regardless of file remove result.
				_ = h.deleteTokenRecord(ctx, filepath.Base(filePath))
			}
			continue
		}

		// --- Skip quota-exceeded entries ---
		if auth.Quota.Exceeded {
			continue
		}

		// --- Only check entries in error state with a last error ---
		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			// Auth recovered or is healthy: reset counter.
			if _, had := failCounts[auth.ID]; had {
				delete(failCounts, auth.ID)
				statRecovered++
				log.Debugf("codex cleanup: auth %s recovered, reset failure counter", auth.ID)
			}
			continue
		}

		// --- Check for permanent failure ---
		if !isPermanentCodexFailure(auth.LastError) {
			// Error is present but not permanent: reset counter.
			if _, had := failCounts[auth.ID]; had {
				delete(failCounts, auth.ID)
				statRecovered++
			}
			continue
		}

		failCounts[auth.ID]++
		if failCounts[auth.ID] < codexCleanupDeleteThreshold {
			log.Debugf("codex cleanup: auth %s permanent failure detected, count=%d (threshold=%d)", auth.ID, failCounts[auth.ID], codexCleanupDeleteThreshold)
			continue
		}

		// --- Delete the permanently failed auth ---
		log.Warnf("codex cleanup: removing permanently invalid auth %s (error: %s)", auth.ID, auth.LastError.Message)
		if filePath != "" {
			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				log.Errorf("codex cleanup: failed to remove file for auth %s: %v", auth.ID, err)
			}
			_ = h.deleteTokenRecord(ctx, filepath.Base(filePath))
		}
		h.disableAuth(ctx, auth.ID)
		delete(failCounts, auth.ID)
		statDeleted++
	}

	// Prune failCounts for IDs that are no longer present.
	for id := range failCounts {
		if _, ok := activeIDs[id]; !ok {
			delete(failCounts, id)
		}
	}

	if statScanned > 0 || statDeleted > 0 || statDisabledCleaned > 0 {
		log.Debugf("codex cleanup: scan complete — scanned=%d disabled_cleaned=%d deleted=%d recovered=%d",
			statScanned, statDisabledCleaned, statDeleted, statRecovered)
	}
}

// resolveAuthFilePath determines the filesystem path for the given auth entry.
func (h *Handler) resolveAuthFilePath(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	filename := strings.TrimSpace(auth.FileName)
	if filename == "" {
		filename = strings.TrimSpace(auth.ID)
	}
	if filename == "" {
		return ""
	}
	if filepath.IsAbs(filename) {
		return filename
	}
	if h.cfg != nil && h.cfg.AuthDir != "" {
		return filepath.Join(h.cfg.AuthDir, filename)
	}
	return filename
}

// isPermanentCodexFailure checks whether the error indicates a permanently
// invalid token that cannot be recovered by retrying or refreshing.
func isPermanentCodexFailure(e *coreauth.Error) bool {
	if e == nil {
		return false
	}
	msg := strings.ToLower(e.Message)

	// Guard: never auto-delete for common transient/quota errors.
	for _, excluded := range []string{
		"unauthorized",
		"payment_required",
		"quota exhausted",
		"usage_limit_reached",
		"request failed",
	} {
		if strings.Contains(msg, excluded) {
			return false
		}
	}
	// Guard: never auto-delete for HTTP 401/403/429 unless the message also
	// contains one of the permanent keywords (checked below).
	if e.HTTPStatus == 401 || e.HTTPStatus == 403 || e.HTTPStatus == 429 {
		// Only proceed if a permanent keyword is found.
		hasPermanent := false
		for _, kw := range permanentFailureKeywords {
			if strings.Contains(msg, strings.ToLower(kw)) {
				hasPermanent = true
				break
			}
		}
		if !hasPermanent {
			return false
		}
	}

	for _, kw := range permanentFailureKeywords {
		if strings.Contains(msg, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
