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

// permanentErrorPatterns lists substrings that indicate a permanently invalid Codex token.
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
	codexCleanupThreshold    = 1
)

// Package-level lifetime counters.
var (
	lifetimeRounds          int
	lifetimeTotalAutoDeleted int
	lifetimeTotalRecovered  int
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
		statTotal           = len(codexAuths)
		statActive          int
		statRefreshOK       int
		statError           int
		statQuotaExceeded   int
		statDisabled        int
		statDisabledCleaned int
		statAutoDeleted     int
		statNewInvalid      int
		statKnownInvalid    int
	)

	now := time.Now()
	seenIDs := make(map[string]struct{}, len(codexAuths))

	for _, auth := range codexAuths {
		seenIDs[auth.ID] = struct{}{}
		email := codexAuthEmail(auth)

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

		// --- Disabled account: clean residual files ---
		if auth.Disabled {
			fileName := strings.TrimSpace(auth.FileName)
			if fileName == "" {
				fileName = auth.ID
			}
			var filePath string
			if filepath.IsAbs(fileName) {
				filePath = fileName
			} else {
				filePath = filepath.Join(h.cfg.AuthDir, fileName)
			}

			err := os.Remove(filePath)
			if err == nil {
				statDisabledCleaned++
				log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record", auth.ID, email)
				_ = h.deleteTokenRecord(ctx, fileName)
			} else if !os.IsNotExist(err) {
				log.Warnf("codex cleanup: failed to remove file for disabled account %s: %v", auth.ID, err)
			} else {
				// File already gone — still try to clean token record silently.
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
			// Account looks healthy — reset counter if previously tracked.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		reason := matchPermanentError(auth.LastError.Message)
		if reason == "" {
			// Error is not a permanent-failure pattern — reset counter.
			if prev, ok := invalidCounts[auth.ID]; ok && prev > 0 {
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
				delete(invalidCounts, auth.ID)
				lifetimeTotalRecovered++
			}
			continue
		}

		// Increment consecutive invalid count.
		invalidCounts[auth.ID]++
		count := invalidCounts[auth.ID]

		log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", auth.ID, email, count, codexCleanupThreshold, reason)

		if count < codexCleanupThreshold {
			statNewInvalid++
			continue
		}

		// --- Auto-delete ---
		fileName := strings.TrimSpace(auth.FileName)
		if fileName == "" {
			fileName = auth.ID
		}
		var filePath string
		if filepath.IsAbs(fileName) {
			filePath = fileName
		} else {
			filePath = filepath.Join(h.cfg.AuthDir, fileName)
		}

		_ = os.Remove(filePath)
		_ = h.deleteTokenRecord(ctx, fileName)
		h.disableAuth(ctx, auth.ID)

		log.Warnf("codex cleanup: auto-deleted %s (%s) after %d check — reason: %s", auth.ID, email, count, reason)

		statAutoDeleted++
		lifetimeTotalAutoDeleted++
		delete(invalidCounts, auth.ID)

		// Notify mail service for deactivated accounts.
		if strings.Contains(reason, "deactivated") && email != "" {
			go notifyMailServiceDelete(email)
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

	// Tally currently-invalid accounts (new + known).
	for id := range invalidCounts {
		if _, exists := seenIDs[id]; exists {
			statKnownInvalid++
		}
	}
	totalInvalid := statNewInvalid + statKnownInvalid

	if totalInvalid > 0 || statAutoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted",
			totalInvalid, statNewInvalid, statKnownInvalid, statAutoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		statTotal, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		lifetimeRounds, lifetimeTotalAutoDeleted, lifetimeTotalRecovered, lifetimeTotalDisabledCleaned)
}

// matchPermanentError checks whether msg matches any known permanent-failure pattern.
// Returns the matched reason string or empty if no match.
func matchPermanentError(msg string) string {
	lower := strings.ToLower(msg)
	for _, parts := range permanentErrorPatterns {
		matched := true
		for _, p := range parts {
			if !strings.Contains(lower, strings.ToLower(p)) {
				matched = false
				break
			}
		}
		if matched {
			return strings.Join(parts, " + ")
		}
	}
	return ""
}

// codexAuthEmail extracts the email from auth metadata.
func codexAuthEmail(auth *coreauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	if email, ok := auth.Metadata["email"].(string); ok {
		return strings.TrimSpace(email)
	}
	return ""
}

// notifyMailServiceDelete sends an HTTP DELETE to the mail service to remove
// the account associated with the given email. Retries up to 3 times.
func notifyMailServiceDelete(email string) {
	client := &http.Client{Timeout: 10 * time.Second}
	targetURL := fmt.Sprintf("http://smtp.aidzpt.com:8025/account?email=%s", url.QueryEscape(email))

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodDelete, targetURL, nil)
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
