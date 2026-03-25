package management

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	codexCleanupInitialDelay     = 30 * time.Second
	codexCleanupInterval         = 1 * time.Minute
	codexCleanupRefreshOKWindow  = 10 * time.Minute
	codexCleanupInvalidThreshold = 1
	codexCleanupNotifyTimeout    = 5 * time.Second
)

var codexCleanupPermanentErrorSubstrings = []string{
	"token has been invalidated",
	"account has been deactivated",
}

type codexCleanupRoundStats struct {
	total           int
	active          int
	refreshOK       int
	errorCount      int
	quotaExceeded   int
	disabled        int
	disabledCleaned int
	invalidTotal    int
	invalidNew      int
	invalidKnown    int
	autoDeleted     int
	recovered       int
}

// StartCodexCleanup launches the background Codex cleanup loop once per handler instance.
func (h *Handler) StartCodexCleanup(ctx context.Context) {
	if h == nil || h.authManager == nil || ctx == nil {
		return
	}

	h.cleanupMu.Lock()
	if h.codexCleanupStarted {
		h.cleanupMu.Unlock()
		return
	}
	h.codexCleanupStarted = true
	if h.codexInvalidCounts == nil {
		h.codexInvalidCounts = make(map[string]int)
	}
	h.cleanupMu.Unlock()

	go h.runCodexCleanupLoop(ctx)
}

func (h *Handler) runCodexCleanupLoop(ctx context.Context) {
	defer func() {
		h.cleanupMu.Lock()
		h.codexCleanupStarted = false
		h.cleanupMu.Unlock()
	}()

	initialDelay := time.NewTimer(codexCleanupInitialDelay)
	defer initialDelay.Stop()

	select {
	case <-ctx.Done():
		return
	case <-initialDelay.C:
	}

	h.runCodexCleanupRound(ctx)

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.runCodexCleanupRound(ctx)
		}
	}
}

func (h *Handler) runCodexCleanupRound(ctx context.Context) {
	if h == nil || h.authManager == nil {
		return
	}

	auths := h.authManager.List()
	codexAuths := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if !isCodexCleanupAuth(auth) {
			continue
		}
		codexAuths = append(codexAuths, auth)
	}

	stats := codexCleanupRoundStats{total: len(codexAuths)}
	log.Debugf("codex cleanup: scanning %d codex accounts", stats.total)

	now := time.Now()
	seenIDs := make(map[string]struct{}, len(codexAuths))
	if h.codexInvalidCounts == nil {
		h.codexInvalidCounts = make(map[string]int)
	}

	for _, auth := range codexAuths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		id := strings.TrimSpace(auth.ID)
		if id == "" {
			id = h.codexCleanupFileName(auth)
		}
		if id != "" {
			seenIDs[id] = struct{}{}
		}

		if auth.Status == coreauth.StatusActive {
			stats.active++
			if !auth.LastRefreshedAt.IsZero() && now.Sub(auth.LastRefreshedAt) <= codexCleanupRefreshOKWindow {
				stats.refreshOK++
			}
		}
		if auth.Status == coreauth.StatusError {
			stats.errorCount++
		}
		if auth.Quota.Exceeded {
			stats.quotaExceeded++
		}
		if auth.Disabled {
			stats.disabled++
		}

		if auth.Disabled {
			delete(h.codexInvalidCounts, id)
			if h.cleanupDisabledCodexAuth(ctx, auth) {
				stats.disabledCleaned++
			}
			continue
		}

		reason, permanentlyInvalid := codexCleanupReason(auth)
		if auth.Quota.Exceeded || auth.Status != coreauth.StatusError || auth.LastError == nil || !permanentlyInvalid {
			if _, ok := h.codexInvalidCounts[id]; ok {
				delete(h.codexInvalidCounts, id)
				stats.recovered++
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", id, authEmail(auth))
			}
			continue
		}

		stats.invalidTotal++
		previous := h.codexInvalidCounts[id]
		if previous > 0 {
			stats.invalidKnown++
		} else {
			stats.invalidNew++
		}
		current := previous + 1
		h.codexInvalidCounts[id] = current
		log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", id, authEmail(auth), current, codexCleanupInvalidThreshold, reason)

		if current < codexCleanupInvalidThreshold {
			continue
		}
		if h.autoDeleteCodexAuth(ctx, auth, reason) {
			stats.autoDeleted++
			delete(h.codexInvalidCounts, id)
		}
	}

	for id := range h.codexInvalidCounts {
		if _, ok := seenIDs[id]; !ok {
			delete(h.codexInvalidCounts, id)
		}
	}

	h.codexCleanupRounds++
	h.codexCleanupTotalAutoDeleted += stats.autoDeleted
	h.codexCleanupTotalRecovered += stats.recovered
	h.codexCleanupTotalDisabledCleaned += stats.disabledCleaned

	if stats.invalidTotal > 0 || stats.autoDeleted > 0 || stats.recovered > 0 || stats.disabledCleaned > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", stats.invalidTotal, stats.invalidNew, stats.invalidKnown, stats.autoDeleted)
	}
	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d", stats.total, stats.active, stats.refreshOK, stats.errorCount, stats.quotaExceeded, stats.disabled, stats.disabledCleaned)
	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d", h.codexCleanupRounds, h.codexCleanupTotalAutoDeleted, h.codexCleanupTotalRecovered, h.codexCleanupTotalDisabledCleaned)
}

func isCodexCleanupAuth(auth *coreauth.Auth) bool {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return false
	}
	if accountType, _ := auth.AccountInfo(); accountType == "api_key" || accountType == "personal_access_token" {
		return false
	}
	if auth.Attributes != nil && strings.EqualFold(strings.TrimSpace(auth.Attributes["auth_kind"]), "apikey") {
		return false
	}
	return true
}

func codexCleanupReason(auth *coreauth.Auth) (string, bool) {
	if auth == nil || auth.LastError == nil {
		return "", false
	}
	message := strings.TrimSpace(auth.LastError.Message)
	if message == "" {
		return "", false
	}
	lowered := strings.ToLower(message)
	for _, needle := range codexCleanupPermanentErrorSubstrings {
		if strings.Contains(lowered, needle) {
			return message, true
		}
	}
	return message, false
}

func (h *Handler) cleanupDisabledCodexAuth(ctx context.Context, auth *coreauth.Auth) bool {
	fileName, fullPath := h.codexCleanupTarget(auth)
	if fileName == "" || fullPath == "" {
		return false
	}

	errRemove := os.Remove(fullPath)
	if errDelete := h.deleteTokenRecord(ctx, fileName); errDelete != nil {
		log.Warnf("codex cleanup: failed to delete token record for disabled account %s (%s): %v", auth.ID, authEmail(auth), errDelete)
	}

	switch {
	case errRemove == nil:
		log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record (%s)", auth.ID, authEmail(auth), fullPath)
		return true
	case os.IsNotExist(errRemove):
		return false
	default:
		log.Warnf("codex cleanup: failed to remove disabled account file for %s (%s): %v", auth.ID, authEmail(auth), errRemove)
		return false
	}
}

func (h *Handler) autoDeleteCodexAuth(ctx context.Context, auth *coreauth.Auth, reason string) bool {
	fileName, fullPath := h.codexCleanupTarget(auth)
	removedOrMissing := false
	if fullPath != "" {
		errRemove := os.Remove(fullPath)
		switch {
		case errRemove == nil:
			removedOrMissing = true
		case os.IsNotExist(errRemove):
			removedOrMissing = true
		default:
			log.Warnf("codex cleanup: failed to remove auth file for %s (%s): %v", auth.ID, authEmail(auth), errRemove)
		}
	}
	if fileName != "" {
		if errDelete := h.deleteTokenRecord(ctx, fileName); errDelete != nil {
			log.Warnf("codex cleanup: failed to delete token record for %s (%s): %v", auth.ID, authEmail(auth), errDelete)
		}
	}
	h.disableAuth(ctx, auth.ID)
	if !removedOrMissing {
		return false
	}
	h.notifyCodexCleanupDeletion(ctx, auth, reason)
	log.Warnf("codex cleanup: auto-deleted %s (%s) after %d check — reason: %s", auth.ID, authEmail(auth), codexCleanupInvalidThreshold, reason)
	return true
}

func (h *Handler) codexCleanupTarget(auth *coreauth.Auth) (string, string) {
	fileName := h.codexCleanupFileName(auth)
	if fileName == "" {
		return "", ""
	}
	return fileName, h.codexCleanupFilePath(fileName)
}

func (h *Handler) codexCleanupFileName(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	fileName := strings.TrimSpace(auth.FileName)
	if fileName == "" {
		fileName = strings.TrimSpace(auth.ID)
	}
	return fileName
}

func (h *Handler) codexCleanupFilePath(fileName string) string {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" {
		return ""
	}
	if filepath.IsAbs(fileName) {
		return fileName
	}
	if h == nil || h.cfg == nil || strings.TrimSpace(h.cfg.AuthDir) == "" {
		return fileName
	}
	return filepath.Join(h.cfg.AuthDir, fileName)
}

func (h *Handler) notifyCodexCleanupDeletion(ctx context.Context, auth *coreauth.Auth, reason string) {
	if h == nil || auth == nil {
		return
	}
	baseURL, err := h.managementCallbackURL("/")
	if err != nil {
		return
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	query := parsedURL.Query()
	query.Set("event", "codex_cleanup")
	query.Set("action", "auto_deleted")
	query.Set("provider", "codex")
	query.Set("auth_id", strings.TrimSpace(auth.ID))
	if email := authEmail(auth); email != "" {
		query.Set("email", email)
	}
	if trimmedReason := strings.TrimSpace(reason); trimmedReason != "" {
		query.Set("reason", trimmedReason)
	}
	parsedURL.RawQuery = query.Encode()

	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return
	}
	notifyCtx, cancel := context.WithTimeout(ctx, codexCleanupNotifyTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(notifyCtx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return
	}
	req.Header.Set("X-CLIProxy-Internal-Notification", "codex-cleanup")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("codex cleanup: notification failed for %s (%s): %v", auth.ID, authEmail(auth), err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}
