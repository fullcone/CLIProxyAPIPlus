package config

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
)

type IPv6Pool struct {
	mu     sync.RWMutex
	netIP  net.IP
	ones   int
	bits   int
	authTo map[string]string
	used   map[string]struct{}
}

var (
	ipv6PoolOnce sync.Once
	ipv6PoolInst *IPv6Pool
)

func GetIPv6Pool(cidr string) *IPv6Pool {
	trimmed := strings.TrimSpace(cidr)
	if trimmed == "" {
		return nil
	}

	ipv6PoolOnce.Do(func() {
		pool, err := NewIPv6Pool(trimmed)
		if err != nil {
			return
		}
		ipv6PoolInst = pool
	})

	return ipv6PoolInst
}

func NewIPv6Pool(cidr string) (*IPv6Pool, error) {
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("parse ipv6 cidr failed: %w", err)
	}
	ipv6 := ip.To16()
	if ipv6 == nil || ip.To4() != nil {
		return nil, fmt.Errorf("cidr is not ipv6: %s", cidr)
	}
	if ipNet == nil {
		return nil, fmt.Errorf("cidr is empty: %s", cidr)
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("cidr is not ipv6: %s", cidr)
	}
	if ones < 0 || ones > 128 {
		return nil, fmt.Errorf("invalid ipv6 prefix length: %d", ones)
	}

	networkIP := make(net.IP, len(ipNet.IP))
	copy(networkIP, ipNet.IP.To16())

	return &IPv6Pool{
		netIP:  networkIP,
		ones:   ones,
		bits:   bits,
		authTo: make(map[string]string),
		used:   make(map[string]struct{}),
	}, nil
}

func (p *IPv6Pool) Assign(authID string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("ipv6 pool is nil")
	}
	id := strings.TrimSpace(authID)
	if id == "" {
		return "", fmt.Errorf("auth id is empty")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.authTo[id]; ok && existing != "" {
		return existing, nil
	}

	ip, err := p.generateUniqueLocked()
	if err != nil {
		return "", err
	}

	p.authTo[id] = ip
	p.used[ip] = struct{}{}
	return ip, nil
}

func (p *IPv6Pool) Register(authID, ipv6 string) error {
	if p == nil {
		return fmt.Errorf("ipv6 pool is nil")
	}
	id := strings.TrimSpace(authID)
	if id == "" {
		return fmt.Errorf("auth id is empty")
	}
	parsed, err := p.validateIPv6(ipv6)
	if err != nil {
		return err
	}
	ipStr := parsed.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	current, hasCurrent := p.authTo[id]
	if hasCurrent && current == ipStr {
		p.used[ipStr] = struct{}{}
		return nil
	}

	if owner, exists := p.findOwnerByIPLocked(ipStr); exists && owner != id {
		return fmt.Errorf("ipv6 %s already assigned to %s", ipStr, owner)
	}

	if hasCurrent && current != "" {
		delete(p.used, current)
	}
	p.authTo[id] = ipStr
	p.used[ipStr] = struct{}{}
	return nil
}

func (p *IPv6Pool) Unregister(authID string) {
	if p == nil {
		return
	}
	id := strings.TrimSpace(authID)
	if id == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	ip, ok := p.authTo[id]
	if !ok {
		return
	}
	delete(p.authTo, id)
	delete(p.used, ip)
}

func (p *IPv6Pool) Get(authID string) (string, bool) {
	if p == nil {
		return "", false
	}
	id := strings.TrimSpace(authID)
	if id == "" {
		return "", false
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	ip, ok := p.authTo[id]
	return ip, ok
}

func (p *IPv6Pool) generateUniqueLocked() (string, error) {
	for {
		candidate := make(net.IP, len(p.netIP))
		copy(candidate, p.netIP)

		hostBits := p.bits - p.ones
		if hostBits > 0 {
			randomBytes := make([]byte, len(candidate))
			if _, err := rand.Read(randomBytes); err != nil {
				return "", fmt.Errorf("generate random ipv6 failed: %w", err)
			}
			fullBytes := p.ones / 8
			if rem := p.ones % 8; rem != 0 {
				idx := fullBytes
				mask := byte(0xFF << uint(8-rem))
				candidate[idx] = (p.netIP[idx] & mask) | (randomBytes[idx] &^ mask)
				fullBytes++
			}
			for i := fullBytes; i < len(candidate); i++ {
				candidate[i] = randomBytes[i]
			}
		}

		if p.isLowAddress(candidate) {
			continue
		}

		ipStr := candidate.String()
		if _, exists := p.used[ipStr]; exists {
			continue
		}
		return ipStr, nil
	}
}

func (p *IPv6Pool) isLowAddress(ip net.IP) bool {
	if len(ip) != net.IPv6len {
		return false
	}
	start := p.ones / 8
	if start >= 15 {
		start = 15
	}
	allZero := true
	for i := start; i <= 14; i++ {
		if ip[i] != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		return false
	}
	return ip[15] <= 200
}

func (p *IPv6Pool) validateIPv6(raw string) (net.IP, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("ipv6 is empty")
	}
	ip := net.ParseIP(trimmed)
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid ipv6: %s", raw)
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil, fmt.Errorf("invalid ipv6: %s", raw)
	}
	if !p.contains(v6) {
		return nil, fmt.Errorf("ipv6 not in pool cidr: %s", raw)
	}
	return v6, nil
}

func (p *IPv6Pool) contains(ip net.IP) bool {
	if len(ip) != net.IPv6len || len(p.netIP) != net.IPv6len {
		return false
	}
	fullBytes := p.ones / 8
	for i := 0; i < fullBytes; i++ {
		if ip[i] != p.netIP[i] {
			return false
		}
	}
	if rem := p.ones % 8; rem != 0 {
		idx := fullBytes
		mask := byte(0xFF << uint(8-rem))
		if (ip[idx] & mask) != (p.netIP[idx] & mask) {
			return false
		}
	}
	return true
}

func (p *IPv6Pool) findOwnerByIPLocked(ip string) (string, bool) {
	for authID, assigned := range p.authTo {
		if assigned == ip {
			return authID, true
		}
	}
	return "", false
}
