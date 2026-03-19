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
	codexCleanupStartDelay       = 30 * time.Second
	codexCleanupInterval         = 1 * time.Minute
	codexCleanupRefreshOKWindow  = 10 * time.Minute
	codexCleanupInvalidThreshold = 1
)

var (
	codexCleanupOnce                 sync.Once
	codexCleanupInvalidCounts        = make(map[string]int)
	codexCleanupRounds               int
	codexCleanupTotalAutoDeleted     int
	codexCleanupTotalRecovered       int
	codexCleanupTotalDisabledCleaned int
)

func (h *Handler) StartCodexCleanup(ctx context.Context) {
	if h == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	codexCleanupOnce.Do(func() {
		go h.runCodexCleanupLoop(ctx)
	})
}

func (h *Handler) runCodexCleanupLoop(ctx context.Context) {
	timer := time.NewTimer(codexCleanupStartDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	ticker := time.NewTicker(codexCleanupInterval)
	defer ticker.Stop()
	for {
		h.runCodexCleanupRound(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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
		if auth == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
			codexAuths = append(codexAuths, auth)
		}
	}

	log.Debugf("codex cleanup: scanning %d codex accounts", len(codexAuths))

	now := time.Now()
	statActive := 0
	statRefreshOK := 0
	statError := 0
	statQuotaExceeded := 0
	statDisabled := 0
	statDisabledCleaned := 0
	statInvalid := 0
	statInvalidNew := 0
	statInvalidKnown := 0
	statAutoDeleted := 0

	for _, auth := range codexAuths {
		if auth == nil {
			continue
		}
		email := authEmail(auth)
		if auth.Status == coreauth.StatusActive {
			statActive++
			if !auth.LastRefreshedAt.IsZero() && now.Sub(auth.LastRefreshedAt) <= codexCleanupRefreshOKWindow {
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
			if h.cleanupDisabledCodexAuth(ctx, auth, email) {
				statDisabledCleaned++
				codexCleanupTotalDisabledCleaned++
			}
			if key := codexCleanupKey(auth); key != "" {
				delete(codexCleanupInvalidCounts, key)
			}
			continue
		}
		if auth.Quota.Exceeded || auth.Status != coreauth.StatusError || auth.LastError == nil {
			if key := codexCleanupKey(auth); key != "" && codexCleanupInvalidCounts[key] > 0 {
				delete(codexCleanupInvalidCounts, key)
				codexCleanupTotalRecovered++
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
			}
			continue
		}

		invalid, reason := codexPermanentInvalidReason(auth.LastError.Message)
		key := codexCleanupKey(auth)
		if !invalid {
			if key != "" && codexCleanupInvalidCounts[key] > 0 {
				delete(codexCleanupInvalidCounts, key)
				codexCleanupTotalRecovered++
				log.Infof("codex cleanup: %s (%s) recovered, resetting counter", auth.ID, email)
			}
			continue
		}

		statInvalid++
		previous := 0
		if key != "" {
			previous = codexCleanupInvalidCounts[key]
			codexCleanupInvalidCounts[key] = previous + 1
		}
		if previous == 0 {
			statInvalidNew++
		} else {
			statInvalidKnown++
		}
		log.Debugf("codex cleanup: %s (%s) invalid count %d/%d — reason: %s", auth.ID, email, previous+1, codexCleanupInvalidThreshold, reason)
		if previous+1 < codexCleanupInvalidThreshold {
			continue
		}

		h.autoDeleteCodexAuth(ctx, auth, email, reason)
		statAutoDeleted++
		codexCleanupTotalAutoDeleted++
		if key != "" {
			delete(codexCleanupInvalidCounts, key)
		}
	}

	if statInvalid > 0 || statAutoDeleted > 0 {
		log.Infof("codex cleanup done: %d permanently invalid (%d new, %d known), %d auto-deleted", statInvalid, statInvalidNew, statInvalidKnown, statAutoDeleted)
	}
	log.Infof("codex cleanup summary: total=%d, active=%d, refreshOK=%d, error=%d, quotaExceeded=%d, disabled=%d, disabledCleaned=%d",
		len(codexAuths), statActive, statRefreshOK, statError, statQuotaExceeded, statDisabled, statDisabledCleaned)

	codexCleanupRounds++
	log.Infof("codex cleanup lifetime: rounds=%d, totalAutoDeleted=%d, totalRecovered=%d, totalDisabledCleaned=%d",
		codexCleanupRounds, codexCleanupTotalAutoDeleted, codexCleanupTotalRecovered, codexCleanupTotalDisabledCleaned)
}

func (h *Handler) cleanupDisabledCodexAuth(ctx context.Context, auth *coreauth.Auth, email string) bool {
	fileName, path := h.resolveCodexAuthPath(auth)
	if fileName == "" || path == "" {
		return false
	}
	cleaned := false
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			_ = h.deleteTokenRecord(ctx, path)
			return false
		}
		log.Warnf("codex cleanup: failed to remove disabled account %s (%s) file %s: %v", auth.ID, email, path, err)
		return false
	} else {
		cleaned = true
	}
	_ = h.deleteTokenRecord(ctx, path)
	if cleaned {
		log.Infof("codex cleanup: cleaned disabled account %s (%s) — removed file and token record at %s", auth.ID, email, path)
	}
	return cleaned
}

func (h *Handler) autoDeleteCodexAuth(ctx context.Context, auth *coreauth.Auth, email, reason string) {
	_, path := h.resolveCodexAuthPath(auth)
	if path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Warnf("codex cleanup: failed to remove auth file %s (%s) at %s: %v", auth.ID, email, path, err)
		}
		_ = h.deleteTokenRecord(ctx, path)
	}
	if auth != nil {
		if id := strings.TrimSpace(auth.ID); id != "" {
			h.disableAuth(ctx, id)
		} else if path != "" {
			h.disableAuth(ctx, path)
		}
	}
	log.Warnf("codex cleanup: auto-deleted %s (%s) after %d check — reason: %s", auth.ID, email, codexCleanupInvalidThreshold, reason)
}

func (h *Handler) resolveCodexAuthPath(auth *coreauth.Auth) (string, string) {
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
	if authDir == "" {
		return fileName, fileName
	}
	return fileName, filepath.Join(authDir, fileName)
}

func codexCleanupKey(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	if id := strings.TrimSpace(auth.ID); id != "" {
		return id
	}
	return strings.TrimSpace(auth.FileName)
}

func codexPermanentInvalidReason(message string) (bool, string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return false, ""
	}
	lower := strings.ToLower(message)
	if strings.Contains(lower, "token has been invalidated") {
		return true, message
	}
	if strings.Contains(lower, "account has been deactivated") {
		return true, message
	}
	return false, ""
}
