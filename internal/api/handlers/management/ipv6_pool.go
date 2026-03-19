package management

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	log "github.com/sirupsen/logrus"
)

type IPv6Pool struct {
	mu sync.Mutex

	prefixStr   string
	prefix      *net.IPNet
	prefixIP    net.IP
	prefixBits  int
	prefixBytes int
	assigned    map[string]string // owner -> ipv6
	owners      map[string]string // ipv6 -> owner
}

func NewIPv6Pool(prefix string) *IPv6Pool {
	return newIPv6Pool(prefix)
}

func newIPv6Pool(prefix string) *IPv6Pool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil
	}
	ip, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		log.Warnf("ipv6 pool: invalid prefix %q: %v", prefix, err)
		return nil
	}
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		log.Warnf("ipv6 pool: prefix %q is not IPv6", prefix)
		return nil
	}
	ones, _ := ipNet.Mask.Size()
	if ones <= 0 || ones >= 128 {
		log.Warnf("ipv6 pool: prefix %q has no host bits", prefix)
		return nil
	}

	prefixIP := ip.Mask(ipNet.Mask)
	prefixBytes := ones / 8
	if ones%8 != 0 {
		prefixBytes++
	}

	return &IPv6Pool{
		prefixStr:   prefix,
		prefix:      ipNet,
		prefixIP:    prefixIP,
		prefixBits:  ones,
		prefixBytes: prefixBytes,
		assigned:    make(map[string]string),
		owners:      make(map[string]string),
	}
}

func (p *IPv6Pool) Assign(owner string) (string, error) {
	if p == nil {
		return "", nil
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return "", fmt.Errorf("ipv6 pool: owner is empty")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.assigned[owner]; ok {
		return existing, nil
	}
	if p.prefix == nil {
		return "", nil
	}
	for attempt := 0; attempt < 1024; attempt++ {
		ip := p.candidateIP(owner, attempt)
		if ip == nil {
			continue
		}
		if isLowIPv6(ip, p.prefixBytes) {
			continue
		}
		ipStr := ip.String()
		if other, ok := p.owners[ipStr]; ok && other != "" {
			continue
		}
		p.assigned[owner] = ipStr
		p.owners[ipStr] = owner
		return ipStr, nil
	}
	return "", fmt.Errorf("ipv6 pool: unable to allocate for %s", owner)
}

func (p *IPv6Pool) Register(owner, ipv6 string) error {
	if p == nil {
		return nil
	}
	owner = strings.TrimSpace(owner)
	ipv6 = strings.TrimSpace(ipv6)
	if owner == "" || ipv6 == "" {
		return fmt.Errorf("ipv6 pool: owner or ipv6 is empty")
	}
	ip := net.ParseIP(ipv6)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return fmt.Errorf("ipv6 pool: invalid ipv6 %q", ipv6)
	}
	ipv6 = ip.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.assigned[owner]; ok {
		if existing == ipv6 {
			return nil
		}
		delete(p.owners, existing)
	}
	if otherOwner, ok := p.owners[ipv6]; ok && otherOwner != owner {
		return fmt.Errorf("ipv6 pool: %s is already assigned to %s", ipv6, otherOwner)
	}
	p.assigned[owner] = ipv6
	p.owners[ipv6] = owner
	return nil
}

func (p *IPv6Pool) Unregister(owner string) {
	if p == nil {
		return
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.assigned[owner]; ok {
		delete(p.assigned, owner)
		if other, ok := p.owners[existing]; ok && other == owner {
			delete(p.owners, existing)
		}
	}
}

func (p *IPv6Pool) Transfer(fromOwner, toOwner string) (string, error) {
	if p == nil {
		return "", nil
	}
	fromOwner = strings.TrimSpace(fromOwner)
	toOwner = strings.TrimSpace(toOwner)
	if fromOwner == "" || toOwner == "" {
		return "", fmt.Errorf("ipv6 pool: transfer owner is empty")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ipv6, ok := p.assigned[fromOwner]
	if !ok || ipv6 == "" {
		return "", fmt.Errorf("ipv6 pool: no assignment for %s", fromOwner)
	}
	if otherOwner, ok := p.owners[ipv6]; ok && otherOwner != "" && otherOwner != fromOwner && otherOwner != toOwner {
		return "", fmt.Errorf("ipv6 pool: %s is already assigned to %s", ipv6, otherOwner)
	}
	delete(p.assigned, fromOwner)
	p.assigned[toOwner] = ipv6
	p.owners[ipv6] = toOwner
	return ipv6, nil
}

func (p *IPv6Pool) candidateIP(owner string, attempt int) net.IP {
	if p == nil || p.prefix == nil {
		return nil
	}
	seed := fmt.Sprintf("%s:%d", owner, attempt)
	sum := sha256.Sum256([]byte(seed))
	ip := make(net.IP, net.IPv6len)
	copy(ip, p.prefixIP)

	start := p.prefixBits / 8
	for i := start; i < net.IPv6len; i++ {
		idx := i - start
		if idx >= len(sum) {
			ip[i] = 0
			continue
		}
		ip[i] = sum[idx]
	}
	if p.prefixBits%8 != 0 {
		maskByte := p.prefix.Mask[start]
		ip[start] = (p.prefixIP[start] & maskByte) | (ip[start] & ^maskByte)
	}
	return ip
}

func isLowIPv6(ip net.IP, hostStart int) bool {
	if ip == nil {
		return false
	}
	ip = ip.To16()
	if ip == nil {
		return false
	}
	if hostStart < 0 || hostStart >= net.IPv6len {
		hostStart = net.IPv6len - 1
	}
	for i := hostStart; i < net.IPv6len-1; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return ip[net.IPv6len-1] <= 200
}

var (
	ipv6PoolMu     sync.Mutex
	ipv6PoolCached *IPv6Pool
	ipv6PoolPrefix string
)

func GetIPv6Pool(cfg *config.Config) *IPv6Pool {
	prefix := ""
	if cfg != nil {
		prefix = strings.TrimSpace(cfg.IPv6Prefix)
	}
	if prefix == "" {
		return nil
	}
	ipv6PoolMu.Lock()
	defer ipv6PoolMu.Unlock()
	if ipv6PoolCached == nil || ipv6PoolPrefix != prefix {
		ipv6PoolCached = newIPv6Pool(prefix)
		ipv6PoolPrefix = prefix
	}
	return ipv6PoolCached
}
