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

const (
	codexCleanupInitialDelay = 30 * time.Second
	codexCleanupInterval     = 1 * time.Minute
	codexRefreshOKWindow     = 10 * time.Minute
	codexInvalidThreshold    = 1
)

var (
	codexCleanupStartOnce sync.Once

	codexCleanupStateMu        sync.Mutex
	codexCleanupInvalidCounts  = make(map[string]int)
	codexCleanupLifetimeRounds int

	codexCleanupLifetimeAutoDeleted     int
	codexCleanupLifetimeRecovered       int
	codexCleanupLifetimeDisabledCleaned int
)

func (h *Handler) StartCodexCleanup(ctx context.Context) {
	if h == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	codexCleanupStartOnce.Do(func() {
		go h.runCodexCleanupLoop(ctx)
	})
}

func (h *Handler) runCodexCleanupLoop(ctx context.Context) {
	firstRun := time.NewTimer(codexCleanupInitialDelay)
	defer firstRun.Stop()

	select {
	case <-ctx.Done():
		return
	case <-firstRun.C:
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
	if ctx == nil {
		ctx = context.Background()
	}

	all := []*coreauth.Auth(nil)
	if h != nil && h.authManager != nil {
		all = h.authManager.List()
	}

	codexAuths := make([]*coreauth.Auth, 0, len(all))
	for i := range all {
		a := all[i]
		if a == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
			codexAuths = append(codexAuths, a)
		}
	}

	log.Debugf("codex cleanup: scanning %d codex accounts", len(codexAuths))

	now := time.Now()
	statTotal := 0
	statActive := 0
	statRefreshOK := 0
	statError := 0
	statQuotaExceeded := 0
	statDisabled := 0
	statDisabledCleaned := 0

	statPermanentInvalid := 0
	statInvalidNew := 0
	statInvalidKnown := 0
	statAutoDeleted := 0
	statRecovered := 0

	for i := range codexAuths {
		auth := codexAuths[i]
		if auth == nil {
			continue
		}

		statTotal++
		email := authEmail(auth)
		displayID := codexCleanupDisplayID(auth)
		accountKey := codexCleanupAccountKey(auth)

		if auth.Status == coreauth.StatusActive {
			statActive++
			if !auth.LastRefreshedAt.IsZero() && now.Sub(auth.LastRefreshedAt) <= codexRefreshOKWindow {
				statRefreshOK++
			}
		}
		if auth.Status == coreauth.StatusError {
			statError++
		}
		if auth.Quota.Exceeded {
			statQuotaExceeded++
		}

		if auth.Disabled {
			statDisabled++
			if h.cleanupDisabledCodexAuth(ctx, auth, email, displayID) {
				statDisabledCleaned++
			}
			if accountKey != "" {
				codexCleanupDeleteCounter(accountKey)
			}
			continue
		}

		if auth.Quota.Exceeded {
			continue
		}

		if auth.Status != coreauth.StatusError || auth.LastError == nil {
			if codexCleanupResetInvalidCounter(accountKey, displayID, email) {
				statRecovered++
			}
			continue
		}

		reason, permanentlyInvalid := codexPermanentInvalidReason(auth.LastError.Message)
		if !permanentlyInvalid {
			if codexCleanupResetInvalidCounter(accountKey, displayID, email) {
				statRecovered++
			}
			continue
		}

		if accountKey == "" {
			continue
		}

		invalidCount, isNew := codexCleanupIncrementCounter(accountKey)
		statPermanentInvalid++
		if isNew {
			statInvalidNew++
		} else {
			statInvalidKnown++
		}
		log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", displayID, email, invalidCount, codexInvalidThreshold, reason)

		if invalidCount < codexInvalidThreshold {
			continue
		}

		if h.autoDeleteCodexAuth(ctx, auth, email, displayID, reason) {
			statAutoDeleted++
		}
		codexCleanupDeleteCounter(accountKey)
	}

	if statPermanentInvalid > 0 || statAutoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", statPermanentInvalid, statInvalidNew, statInvalidKnown, statAutoDeleted)
	}

	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d", statTotal, statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	rounds, totalAutoDeleted, totalRecovered, totalDisabledCleaned := codexCleanupUpdateLifetime(statAutoDeleted, statRecovered, statDisabledCleaned)
	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d", rounds, totalAutoDeleted, totalRecovered, totalDisabledCleaned)
}

func (h *Handler) cleanupDisabledCodexAuth(ctx context.Context, auth *coreauth.Auth, email, displayID string) bool {
	fileName, filePath := h.codexCleanupFileTarget(auth)
	if fileName == "" {
		return false
	}

	err := os.Remove(filePath)
	if err == nil {
		_ = h.deleteTokenRecord(ctx, fileName)
		log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record: %s", displayID, email, filePath)
		return true
	}
	if os.IsNotExist(err) {
		_ = h.deleteTokenRecord(ctx, fileName)
		return false
	}

	log.Warnf("codex cleanup: failed to remove disabled account %s (%s) file %s: %v", displayID, email, filePath, err)
	_ = h.deleteTokenRecord(ctx, fileName)
	return false
}

func (h *Handler) autoDeleteCodexAuth(ctx context.Context, auth *coreauth.Auth, email, displayID, reason string) bool {
	fileName, filePath := h.codexCleanupFileTarget(auth)
	if fileName == "" {
		return false
	}

	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		log.Warnf("codex cleanup: failed to remove %s (%s) file %s: %v", displayID, email, filePath, err)
	}
	_ = h.deleteTokenRecord(ctx, fileName)

	disableKey := strings.TrimSpace(auth.ID)
	if disableKey == "" {
		disableKey = fileName
	}
	h.disableAuth(ctx, disableKey)

	log.Warnf("codex cleanup: auto-deleted %s (%s) after %d check — reason: %s", displayID, email, codexInvalidThreshold, reason)

	if strings.Contains(strings.ToLower(reason), "deactivated") {
		email = strings.TrimSpace(email)
		if email != "" {
			go notifyMailServiceDelete(email)
		}
	}
	return true
}

func (h *Handler) codexCleanupFileTarget(auth *coreauth.Auth) (string, string) {
	if auth == nil {
		return "", ""
	}

	fileName := strings.TrimSpace(auth.FileName)
	if fileName == "" {
		fileName = strings.TrimSpace(auth.ID)
	}
	if fileName == "" {
		return "", ""
	}

	if filepath.IsAbs(fileName) {
		return fileName, fileName
	}
	authDir := ""
	if h != nil && h.cfg != nil {
		authDir = strings.TrimSpace(h.cfg.AuthDir)
	}
	return fileName, filepath.Join(authDir, fileName)
}

func codexCleanupDisplayID(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if id := strings.TrimSpace(auth.ID); id != "" {
		return id
	}
	return strings.TrimSpace(auth.FileName)
}

func codexCleanupAccountKey(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if id := strings.TrimSpace(auth.ID); id != "" {
		return id
	}
	return strings.TrimSpace(auth.FileName)
}

func codexCleanupIncrementCounter(accountKey string) (int, bool) {
	codexCleanupStateMu.Lock()
	defer codexCleanupStateMu.Unlock()
	codexCleanupInvalidCounts[accountKey]++
	count := codexCleanupInvalidCounts[accountKey]
	return count, count == 1
}

func codexCleanupDeleteCounter(accountKey string) {
	codexCleanupStateMu.Lock()
	delete(codexCleanupInvalidCounts, accountKey)
	codexCleanupStateMu.Unlock()
}

func codexCleanupResetInvalidCounter(accountKey, displayID, email string) bool {
	if accountKey == "" {
		return false
	}
	codexCleanupStateMu.Lock()
	_, exists := codexCleanupInvalidCounts[accountKey]
	if exists {
		delete(codexCleanupInvalidCounts, accountKey)
	}
	codexCleanupStateMu.Unlock()
	if !exists {
		return false
	}
	log.Infof("codex cleanup: %s (%s) recovered, resetting counter", displayID, email)
	return true
}

func codexCleanupUpdateLifetime(autoDeleted, recovered, disabledCleaned int) (int, int, int, int) {
	codexCleanupStateMu.Lock()
	defer codexCleanupStateMu.Unlock()
	codexCleanupLifetimeRounds++
	codexCleanupLifetimeAutoDeleted += autoDeleted
	codexCleanupLifetimeRecovered += recovered
	codexCleanupLifetimeDisabledCleaned += disabledCleaned
	return codexCleanupLifetimeRounds, codexCleanupLifetimeAutoDeleted, codexCleanupLifetimeRecovered, codexCleanupLifetimeDisabledCleaned
}

func codexPermanentInvalidReason(message string) (string, bool) {
	reason := strings.TrimSpace(message)
	if reason == "" {
		return "", false
	}
	lower := strings.ToLower(reason)

	if strings.Contains(lower, "token refresh failed") && strings.Contains(lower, "invalid_grant") {
		return reason, true
	}
	if strings.Contains(lower, "token refresh failed") && strings.Contains(lower, "status 403") {
		return reason, true
	}
	if strings.Contains(lower, "token refresh failed") && strings.Contains(lower, "status 401") {
		return reason, true
	}
	if strings.Contains(lower, "token has been invalidated") {
		return reason, true
	}
	if strings.Contains(lower, "token is expired") {
		return reason, true
	}
	if strings.Contains(lower, "account has been deactivated") {
		return reason, true
	}
	return "", false
}

func notifyMailServiceDelete(email string) {
	email = strings.TrimSpace(email)
	if email == "" {
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	target := fmt.Sprintf("http://smtp.aidzpt.com:8025/account?email=%s", url.QueryEscape(email))

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodDelete, target, nil)
		if err != nil {
			lastErr = err
		} else {
			resp, errDo := client.Do(req)
			if errDo != nil {
				lastErr = errDo
			} else {
				_ = resp.Body.Close()
				if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
					log.Infof("codex cleanup: notified mail service to delete account %s", email)
					return
				}
				lastErr = fmt.Errorf("status %d", resp.StatusCode)
			}
		}
		if attempt < 3 {
			time.Sleep(2 * time.Second)
		}
	}

	log.Warnf("codex cleanup: failed to notify mail service for %s after 3 retries: %v", email, lastErr)
}
