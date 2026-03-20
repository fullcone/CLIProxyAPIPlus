package management

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"
)

const immediateAuthRegistrationQueueSize = 256

func (h *Handler) startImmediateAuthRegistrationWorker() {
	if h == nil {
		return
	}
	h.immediateAuthMu.Lock()
	defer h.immediateAuthMu.Unlock()
	if h.immediateAuthQueue != nil {
		return
	}
	h.immediateAuthQueue = make(chan string, immediateAuthRegistrationQueueSize)
	h.immediateAuthDirty = make(map[string]bool)
	go h.consumeImmediateAuthRegistrations()
}

func (h *Handler) enqueueImmediateAuthRegistration(path string) bool {
	if h == nil || h.authManager == nil {
		return false
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}

	h.immediateAuthMu.Lock()
	defer h.immediateAuthMu.Unlock()
	if h.immediateAuthQueue == nil {
		return false
	}
	if _, exists := h.immediateAuthDirty[path]; exists {
		h.immediateAuthDirty[path] = true
		return true
	}
	h.immediateAuthDirty[path] = false
	select {
	case h.immediateAuthQueue <- path:
		return true
	default:
		delete(h.immediateAuthDirty, path)
		return false
	}
}

func (h *Handler) consumeImmediateAuthRegistrations() {
	if h == nil {
		return
	}
	for path := range h.immediateAuthQueue {
		for {
			if h.authManager != nil {
				if err := h.registerAuthFromFile(context.Background(), path, nil); err != nil {
					log.Warnf("immediate auth registration failed for %s: %v", path, err)
				}
			}
			if !h.finishImmediateAuthRegistration(path) {
				break
			}
		}
	}
}

func (h *Handler) finishImmediateAuthRegistration(path string) bool {
	if h == nil {
		return false
	}
	h.immediateAuthMu.Lock()
	defer h.immediateAuthMu.Unlock()
	if h.immediateAuthDirty == nil {
		return false
	}
	dirty, ok := h.immediateAuthDirty[path]
	if !ok {
		return false
	}
	if dirty {
		h.immediateAuthDirty[path] = false
		return true
	}
	delete(h.immediateAuthDirty, path)
	return false
}
