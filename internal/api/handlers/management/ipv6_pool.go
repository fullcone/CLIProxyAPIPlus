package management

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var (
	codexIPv6PoolsMu sync.Mutex
	codexIPv6Pools   = make(map[string]*codexIPv6Pool)
)

type codexIPv6Pool struct {
	mu sync.Mutex

	prefix  netip.Prefix
	authDir string

	ownerToIP map[string]string
	ipToOwner map[string]string

	bootstrapOnce sync.Once
	bootstrapErr  error
}

func NewCodexIPv6PostAuthHook(cfg *config.Config) coreauth.PostAuthHook {
	if cfg == nil || strings.TrimSpace(cfg.IPv6Prefix) == "" {
		return nil
	}
	return func(_ context.Context, record *coreauth.Auth) error {
		if record == nil || !strings.EqualFold(strings.TrimSpace(record.Provider), "codex") {
			return nil
		}
		pool, err := codexIPv6PoolForConfig(cfg)
		if err != nil {
			return err
		}
		if pool == nil {
			return nil
		}
		owner := codexIPv6OwnerKey(record)
		if owner == "" {
			return nil
		}
		if record.Metadata == nil {
			record.Metadata = make(map[string]any)
		}
		if existing, ok := codexIPv6MetadataValue(record.Metadata); ok {
			if errRegister := pool.Register(owner, existing); errRegister != nil {
				log.WithError(errRegister).Warnf("codex ipv6 pool: keep existing IPv6 for owner %s", owner)
			}
			record.Metadata["ipv6"] = existing
			return nil
		}
		ipv6, err := pool.Assign(owner)
		if err != nil {
			return err
		}
		record.Metadata["ipv6"] = ipv6
		return nil
	}
}

func codexIPv6PoolForConfig(cfg *config.Config) (*codexIPv6Pool, error) {
	if cfg == nil {
		return nil, nil
	}
	prefixText := strings.TrimSpace(cfg.IPv6Prefix)
	if prefixText == "" {
		return nil, nil
	}
	prefix, err := netip.ParsePrefix(prefixText)
	if err != nil {
		return nil, fmt.Errorf("invalid ipv6-prefix %q: %w", prefixText, err)
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is6() {
		return nil, fmt.Errorf("ipv6-prefix %q is not IPv6", prefixText)
	}

	authDir := strings.TrimSpace(cfg.AuthDir)
	if resolvedAuthDir, errResolve := util.ResolveAuthDir(authDir); errResolve == nil && resolvedAuthDir != "" {
		authDir = resolvedAuthDir
	}
	if authDir != "" {
		authDir = filepath.Clean(authDir)
		if !filepath.IsAbs(authDir) {
			if abs, errAbs := filepath.Abs(authDir); errAbs == nil {
				authDir = abs
			}
		}
	}

	key := prefix.String() + "|" + authDir
	codexIPv6PoolsMu.Lock()
	pool := codexIPv6Pools[key]
	if pool == nil {
		pool = &codexIPv6Pool{
			prefix:    prefix,
			authDir:    authDir,
			ownerToIP: make(map[string]string),
			ipToOwner: make(map[string]string),
		}
		codexIPv6Pools[key] = pool
	}
	codexIPv6PoolsMu.Unlock()

	if errBootstrap := pool.bootstrap(); errBootstrap != nil {
		return nil, errBootstrap
	}
	return pool, nil
}

func reserveCodexIPv6ForOwner(cfg *config.Config, owner string) (string, error) {
	pool, err := codexIPv6PoolForConfig(cfg)
	if err != nil || pool == nil {
		return "", err
	}
	return pool.Assign(owner)
}

func transferCodexIPv6Owner(cfg *config.Config, fromOwner, toOwner, ipv6 string) error {
	pool, err := codexIPv6PoolForConfig(cfg)
	if err != nil || pool == nil {
		return err
	}
	return pool.Transfer(fromOwner, toOwner, ipv6)
}

func releaseCodexIPv6Owner(cfg *config.Config, owner string) {
	pool, err := codexIPv6PoolForConfig(cfg)
	if err != nil || pool == nil {
		return
	}
	pool.Release(owner)
}

func releaseCodexIPv6ForAuth(cfg *config.Config, auth *coreauth.Auth) {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return
	}
	releaseCodexIPv6Owner(cfg, codexIPv6OwnerKey(auth))
}

func codexIPv6OwnerKey(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	owner := strings.TrimSpace(auth.ID)
	if owner == "" {
		owner = strings.TrimSpace(auth.FileName)
	}
	if runtime.GOOS == "windows" {
		owner = strings.ToLower(owner)
	}
	return owner
}

func codexIPv6MetadataValue(metadata map[string]any) (string, bool) {
	if len(metadata) == 0 {
		return "", false
	}
	raw, ok := metadata["ipv6"]
	if !ok || raw == nil {
		return "", false
	}
	text, ok := raw.(string)
	if !ok {
		return "", false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || !addr.Is6() {
		return "", false
	}
	return addr.Unmap().String(), true
}

func (p *codexIPv6Pool) bootstrap() error {
	if p == nil {
		return nil
	}
	p.bootstrapOnce.Do(func() {
		authDir := p.authDir
		if authDir == "" {
			return
		}
		walkErr := filepath.WalkDir(authDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d == nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
				return nil
			}
			data, errRead := os.ReadFile(path)
			if errRead != nil || len(data) == 0 {
				return nil
			}
			var metadata map[string]any
			if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil {
				return nil
			}
			provider, _ := metadata["type"].(string)
			if !strings.EqualFold(strings.TrimSpace(provider), "codex") {
				return nil
			}
			ipv6, ok := codexIPv6MetadataValue(metadata)
			if !ok {
				return nil
			}
			owner := codexIPv6OwnerFromPath(authDir, path)
			if owner == "" {
				return nil
			}
			if errRegister := p.Register(owner, ipv6); errRegister != nil {
				log.WithError(errRegister).Warnf("codex ipv6 pool: skip persisted owner %s from %s", owner, path)
			}
			return nil
		})
		if walkErr != nil && !os.IsNotExist(walkErr) {
			p.bootstrapErr = walkErr
		}
	})
	return p.bootstrapErr
}

func codexIPv6OwnerFromPath(authDir, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		if abs, errAbs := filepath.Abs(path); errAbs == nil {
			path = abs
		}
	}
	owner := path
	if authDir != "" {
		if rel, errRel := filepath.Rel(authDir, path); errRel == nil && rel != "" {
			owner = rel
		}
	}
	if runtime.GOOS == "windows" {
		owner = strings.ToLower(owner)
	}
	return owner
}

func (p *codexIPv6Pool) Assign(owner string) (string, error) {
	if p == nil {
		return "", nil
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return "", fmt.Errorf("codex ipv6 pool: empty owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ipv6, ok := p.ownerToIP[owner]; ok && ipv6 != "" {
		return ipv6, nil
	}
	for attempt := 0; attempt < 4096; attempt++ {
		candidate := p.candidate(owner, attempt)
		if p.isLowAddress(candidate) {
			continue
		}
		ipv6 := candidate.String()
		if existingOwner, ok := p.ipToOwner[ipv6]; ok && existingOwner != "" && existingOwner != owner {
			continue
		}
		p.ownerToIP[owner] = ipv6
		p.ipToOwner[ipv6] = owner
		return ipv6, nil
	}
	return "", fmt.Errorf("codex ipv6 pool: no IPv6 available for owner %s", owner)
}

func (p *codexIPv6Pool) Register(owner, ipv6 string) error {
	if p == nil {
		return nil
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return fmt.Errorf("codex ipv6 pool: empty owner")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipv6))
	if err != nil || !addr.Is6() {
		return fmt.Errorf("codex ipv6 pool: invalid IPv6 %q", ipv6)
	}
	addr = addr.Unmap()
	if !p.prefix.Contains(addr) {
		return fmt.Errorf("codex ipv6 pool: IPv6 %s is outside prefix %s", addr, p.prefix)
	}
	ipv6 = addr.String()

	p.mu.Lock()
	defer p.mu.Unlock()
	if currentIPv6, ok := p.ownerToIP[owner]; ok {
		if currentIPv6 == ipv6 {
			p.ipToOwner[ipv6] = owner
			return nil
		}
		delete(p.ipToOwner, currentIPv6)
	}
	if existingOwner, ok := p.ipToOwner[ipv6]; ok && existingOwner != "" && existingOwner != owner {
		return fmt.Errorf("codex ipv6 pool: IPv6 %s is already assigned to %s", ipv6, existingOwner)
	}
	p.ownerToIP[owner] = ipv6
	p.ipToOwner[ipv6] = owner
	return nil
}

func (p *codexIPv6Pool) Transfer(fromOwner, toOwner, ipv6 string) error {
	if p == nil {
		return nil
	}
	fromOwner = strings.TrimSpace(fromOwner)
	toOwner = strings.TrimSpace(toOwner)
	if fromOwner == "" || toOwner == "" {
		return fmt.Errorf("codex ipv6 pool: transfer owner is empty")
	}
	if fromOwner == toOwner {
		return nil
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipv6))
	if err != nil || !addr.Is6() {
		return fmt.Errorf("codex ipv6 pool: invalid IPv6 %q", ipv6)
	}
	ipv6 = addr.Unmap().String()

	p.mu.Lock()
	defer p.mu.Unlock()
	currentOwner, ok := p.ipToOwner[ipv6]
	if !ok || currentOwner != fromOwner {
		return fmt.Errorf("codex ipv6 pool: IPv6 %s is not owned by %s", ipv6, fromOwner)
	}
	if currentIPv6, ok := p.ownerToIP[fromOwner]; !ok || currentIPv6 != ipv6 {
		return fmt.Errorf("codex ipv6 pool: owner %s does not hold IPv6 %s", fromOwner, ipv6)
	}
	if existingIPv6, ok := p.ownerToIP[toOwner]; ok && existingIPv6 != ipv6 {
		return fmt.Errorf("codex ipv6 pool: owner %s already has IPv6 %s", toOwner, existingIPv6)
	}
	delete(p.ownerToIP, fromOwner)
	p.ownerToIP[toOwner] = ipv6
	p.ipToOwner[ipv6] = toOwner
	return nil
}

func (p *codexIPv6Pool) Release(owner string) {
	if p == nil {
		return
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ipv6 := p.ownerToIP[owner]
	delete(p.ownerToIP, owner)
	if ipv6 == "" {
		return
	}
	if currentOwner, ok := p.ipToOwner[ipv6]; ok && currentOwner == owner {
		delete(p.ipToOwner, ipv6)
	}
}

func (p *codexIPv6Pool) candidate(owner string, attempt int) netip.Addr {
	base := p.prefix.Addr().As16()
	sum := sha256.Sum256([]byte(p.prefix.String() + "\x00" + owner + "\x00" + strconv.Itoa(attempt)))
	bits := p.prefix.Bits()
	fullBytes := bits / 8
	remBits := bits % 8
	if fullBytes >= len(base) {
		return netip.AddrFrom16(base)
	}
	if remBits == 0 {
		copy(base[fullBytes:], sum[fullBytes:])
		return netip.AddrFrom16(base)
	}
	mask := byte(0xff << uint(8-remBits))
	base[fullBytes] = (base[fullBytes] & mask) | (sum[fullBytes] &^ mask)
	copy(base[fullBytes+1:], sum[fullBytes+1:])
	return netip.AddrFrom16(base)
}

func (p *codexIPv6Pool) isLowAddress(addr netip.Addr) bool {
	bytes := addr.As16()
	start := p.prefix.Bits() / 8
	if p.prefix.Bits()%8 != 0 {
		start++
	}
	if start > 15 {
		return false
	}
	for i := start; i < 15; i++ {
		if bytes[i] != 0 {
			return false
		}
	}
	return bytes[15] <= 200
}
