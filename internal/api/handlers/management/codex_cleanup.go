package management

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// permanentErrorPatterns lists substrings that indicate a permanently invalid token.
var permanentErrorPatterns = [][]string{
	{"token refresh failed", "invalid_grant"},
	{"token refresh failed", "status 403"},
	{"token refresh failed", "status 401"},
	{"token has been invalidated"},
	{"token is expired"},
	{"account has been deactivated"},
}

const (
	codexCleanupInitialDelay = 30 * time.Second
	codexCleanupInterval     = 1 * time.Minute
	codexCleanupConfirmCount = 1
)

// Package-level lifetime counters.
var (
	lifetimeRounds              int
	lifetimeTotalAutoDeleted    int
	lifetimeTotalRecovered      int
	lifetimeTotalDisabledCleaned int
)

var codexCleanupOnce sync.Once

// StartCodexCleanup launches the background codex cleanup goroutine.
// It is safe to call multiple times; only the first invocation starts the loop.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	codexCleanupOnce.Do(func() {
		go h.codexCleanupLoop(ctx)
	})
}

func (h *Handler) codexCleanupLoop(ctx context.Context) {
	// invalidCounts tracks consecutive permanent-error detections per auth ID.
	invalidCounts := make(map[string]int)

	select {
	case <-time.After(codexCleanupInitialDelay):
	case <-ctx.Done():
		return
	}

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

	allAuths := h.authManager.List()

	// Filter codex accounts.
	var codexAuths []*coreauth.Auth
	for _, a := range allAuths {
		if strings.ToLower(a.Provider) == "codex" {
			codexAuths = append(codexAuths, a)
		}
	}

	log.Debugf("codex cleanup: scanning %d codex accounts", len(codexAuths))

	lifetimeRounds++

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

	seenIDs := make(map[string]struct{}, len(codexAuths))
	now := time.Now()

	for _, auth := range codexAuths {
		seenIDs[auth.ID] = struct{}{}
		email := ""
		if auth.Metadata != nil {
			if e, ok := auth.Metadata["email"].(string); ok {
				email = strings.TrimSpace(e)
			}
		}

		// Count status.
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

		// Handle disabled accounts: clean up residual files.
		if auth.Disabled {
			fileName := resolveCleanupFileName(auth)
			filePath := resolveCleanupFilePath(h.cfg.AuthDir, fileName)
			err := os.Remove(filePath)
			if err == nil {
				statDisabledCleaned++
				_ = h.deleteTokenRecord(ctx, fileName)
				log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record", auth.ID, email)
			} else if !os.IsNotExist(err) {
				log.Warnf("codex cleanup: failed to remove file for disabled account %s: %v", auth.ID, err)
			}
			continue
		}

		// Skip quota-exceeded accounts.
		if auth.Quota.Exceeded {
			continue
		}

		// Only inspect accounts with StatusError and a LastError.
		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			continue
		}

		reason := isPermanentlyInvalid(auth.LastError.Message)
		if reason == "" {
			// Account recovered or not permanently invalid.
			if invalidCounts[auth.ID] > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// Increment consecutive invalid count.
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]
		log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", auth.ID, email, count, codexCleanupConfirmCount, reason)

		if count < codexCleanupConfirmCount {
			statNewInvalid++
			continue
		}

		// Auto-delete.
		fileName := resolveCleanupFileName(auth)
		filePath := resolveCleanupFilePath(h.cfg.AuthDir, fileName)
		_ = os.Remove(filePath)
		_ = h.deleteTokenRecord(ctx, fileName)
		h.disableAuth(ctx, auth.ID)
		delete(invalidCounts, auth.ID)
		statAutoDeleted++
		lifetimeTotalAutoDeleted++
		log.Warnf("codex cleanup: auto-deleted %s (%s) after %d check — reason: %s", auth.ID, email, count, reason)

		// Notify mail service for deactivated accounts.
		if strings.Contains(reason, "deactivated") && email != "" {
			go notifyMailServiceDelete(email)
		}
	}

	// Purge stale entries from invalidCounts for accounts no longer present.
	for id := range invalidCounts {
		if _, ok := seenIDs[id]; !ok {
			delete(invalidCounts, id)
		}
	}

	// Count new vs known invalid.
	for id := range invalidCounts {
		if _, ok := seenIDs[id]; ok {
			count := invalidCounts[id]
			if count == 1 {
				statNewInvalid++
			} else {
				statKnownInvalid++
			}
		}
	}

	lifetimeTotalDisabledCleaned += statDisabledCleaned

	totalInvalid := statNewInvalid + statKnownInvalid
	if totalInvalid > 0 || statAutoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", totalInvalid, statNewInvalid, statKnownInvalid, statAutoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		statTotal, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		lifetimeRounds, lifetimeTotalAutoDeleted, lifetimeTotalRecovered, lifetimeTotalDisabledCleaned)
}

// resolveCleanupFileName returns the file name to use for cleanup operations.
// It prefers auth.FileName, falling back to auth.ID.
func resolveCleanupFileName(auth *coreauth.Auth) string {
	if fn := strings.TrimSpace(auth.FileName); fn != "" {
		return fn
	}
	return auth.ID
}

// resolveCleanupFilePath builds the full file path for cleanup.
// If the fileName is already absolute, it is used directly; otherwise it is joined with authDir.
func resolveCleanupFilePath(authDir, fileName string) string {
	if filepath.IsAbs(fileName) {
		return fileName
	}
	return filepath.Join(authDir, fileName)
}

// isPermanentlyInvalid checks whether the error message matches any permanent failure pattern.
// Returns the matched reason string, or empty if no match.
func isPermanentlyInvalid(msg string) string {
	lower := strings.ToLower(msg)
	for _, pattern := range permanentErrorPatterns {
		matched := true
		for _, sub := range pattern {
			if !strings.Contains(lower, strings.ToLower(sub)) {
				matched = false
				break
			}
		}
		if matched {
			return msg
		}
	}
	return ""
}

// notifyMailServiceDelete sends an HTTP DELETE to the mail service to remove the account.
// It retries up to 3 times with 2-second intervals.
func notifyMailServiceDelete(email string) {
	client := &http.Client{Timeout: 10 * time.Second}
	endpoint := fmt.Sprintf("http://smtp.aidzpt.com:8025/account?email=%s", url.QueryEscape(email))

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Infof("codex cleanup: notified mail service to delete account %s", email)
			return
		}
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		time.Sleep(2 * time.Second)
	}
	log.Warnf("codex cleanup: failed to notify mail service for %s after 3 retries: %v", email, lastErr)
}
