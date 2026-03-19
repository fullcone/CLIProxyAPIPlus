package management

import (
	"context"
	"net"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// NewCodexIPv6PostAuthHook assigns and persists IPv6 addresses for Codex auth records.
func NewCodexIPv6PostAuthHook(cfg *config.Config) coreauth.PostAuthHook {
	return func(ctx context.Context, record *coreauth.Auth) error {
		_ = ctx
		if record == nil || !strings.EqualFold(strings.TrimSpace(record.Provider), "codex") {
			return nil
		}
		pool := GetIPv6Pool(cfg)
		if pool == nil {
			return nil
		}
		if record.Metadata == nil {
			record.Metadata = make(map[string]any)
		}
		if raw, ok := record.Metadata["ipv6"].(string); ok {
			if ipv6 := strings.TrimSpace(raw); ipv6 != "" && isValidIPv6(ipv6) {
				if err := pool.Register(record.ID, ipv6); err != nil {
					log.Warnf("codex ipv6: register failed for %s: %v", record.ID, err)
				}
				return nil
			}
		}
		ipv6, err := pool.Assign(record.ID)
		if err != nil {
			return err
		}
		if ipv6 != "" {
			record.Metadata["ipv6"] = ipv6
		}
		return nil
	}
}

func isValidIPv6(ipv6 string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipv6))
	if ip == nil {
		return false
	}
	return ip.To16() != nil && ip.To4() == nil
}
