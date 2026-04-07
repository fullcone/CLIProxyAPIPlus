package management

import (
	"context"
	"strings"
	"sync"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// globalIPv6Pool is the singleton pool used by the PostAuthHook.
var (
	globalIPv6Pool     *IPv6Pool
	globalIPv6PoolOnce sync.Once
)

// InitIPv6Pool initialises the global IPv6 address pool from the given CIDR
// prefix.  It is safe to call multiple times; only the first call takes effect.
func InitIPv6Pool(prefix string) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return
	}
	globalIPv6PoolOnce.Do(func() {
		pool, err := NewIPv6Pool(prefix)
		if err != nil {
			log.Errorf("ipv6 pool: failed to initialise: %v", err)
			return
		}
		globalIPv6Pool = pool
		log.Infof("ipv6 pool: initialised with prefix %s", prefix)
	})
}

// GetGlobalIPv6Pool returns the singleton pool, or nil if not initialised.
func GetGlobalIPv6Pool() *IPv6Pool {
	return globalIPv6Pool
}

// NewIPv6PostAuthHook returns a PostAuthHook that allocates a unique IPv6
// address for each new Codex auth record.  The address is stored in
// record.Metadata["ipv6"] and reused on subsequent saves for the same ID.
func NewIPv6PostAuthHook(prefix string) coreauth.PostAuthHook {
	InitIPv6Pool(prefix)
	return func(_ context.Context, record *coreauth.Auth) error {
		if record == nil {
			return nil
		}
		pool := globalIPv6Pool
		if pool == nil {
			return nil
		}
		// Only allocate for codex providers.
		if strings.TrimSpace(strings.ToLower(record.Provider)) != "codex" {
			return nil
		}
		if record.Metadata == nil {
			record.Metadata = make(map[string]any)
		}
		// Skip if already assigned.
		if v, ok := record.Metadata["ipv6"].(string); ok && strings.TrimSpace(v) != "" {
			return nil
		}
		ownerID := strings.TrimSpace(record.ID)
		if ownerID == "" {
			return nil
		}
		addr, err := pool.Allocate(ownerID)
		if err != nil {
			log.Warnf("ipv6 pool: allocation failed for %s: %v", ownerID, err)
			return nil // non-fatal
		}
		record.Metadata["ipv6"] = addr
		log.Debugf("ipv6 pool: allocated %s for auth %s", addr, ownerID)
		return nil
	}
}
