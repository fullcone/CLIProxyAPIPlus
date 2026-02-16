package config

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
)

// IPv6Pool manages per-account IPv6 address allocation from a CIDR prefix.
// It is thread-safe and ensures each authID gets a unique, stable IPv6 address.
type IPv6Pool struct {
	mu      sync.Mutex
	network *net.IPNet
	ones    int // prefix length
	forward map[string]string // authID -> IPv6
	reverse map[string]bool   // IPv6 -> occupied
}

var (
	globalIPv6Pool     *IPv6Pool
	globalIPv6PoolOnce sync.Once
)

// GetIPv6Pool returns the global IPv6Pool singleton. If cidr is empty, returns nil.
func GetIPv6Pool(cidr string) *IPv6Pool {
	if cidr == "" {
		return nil
	}
	globalIPv6PoolOnce.Do(func() {
		pool, err := newIPv6Pool(cidr)
		if err != nil {
			fmt.Printf("WARNING: failed to initialize IPv6 pool from %q: %v\n", cidr, err)
			return
		}
		globalIPv6Pool = pool
	})
	return globalIPv6Pool
}

func newIPv6Pool(cidr string) (*IPv6Pool, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	ones, bits := network.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("expected IPv6 CIDR, got %d-bit network", bits)
	}
	return &IPv6Pool{
		network: network,
		ones:    ones,
		forward: make(map[string]string),
		reverse: make(map[string]bool),
	}, nil
}

// Assign returns the IPv6 address for authID. If not yet assigned, generates a new one.
func (p *IPv6Pool) Assign(authID string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ip, ok := p.forward[authID]; ok {
		return ip, nil
	}

	ip, err := p.generateUnique()
	if err != nil {
		return "", err
	}
	p.forward[authID] = ip
	p.reverse[ip] = true
	return ip, nil
}

// Register records an existing authID -> IPv6 mapping (used at startup to load old accounts).
func (p *IPv6Pool) Register(authID, ipv6 string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.forward[authID] = ipv6
	p.reverse[ipv6] = true
}

// Get returns the IPv6 address for authID, or empty string if not assigned.
func (p *IPv6Pool) Get(authID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.forward[authID]
}

// generateUnique creates a random IPv6 within the prefix that is not yet assigned.
// The last byte must be > 200 to avoid reserved low addresses.
func (p *IPv6Pool) generateUnique() (string, error) {
	prefixBytes := p.ones / 8
	for attempt := 0; attempt < 1000; attempt++ {
		ip := make(net.IP, 16)
		copy(ip, p.network.IP.To16())

		// Fill suffix bytes with random data
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", fmt.Errorf("crypto/rand failed: %w", err)
		}
		for i := prefixBytes; i < 16; i++ {
			ip[i] = suffix[i]
		}
		// Handle partial byte at prefix boundary
		if remainder := p.ones % 8; remainder != 0 {
			mask := byte(0xFF << (8 - remainder))
			ip[prefixBytes] = (p.network.IP.To16()[prefixBytes] & mask) | (suffix[prefixBytes] & ^mask)
		}

		// Exclude addresses where last byte <= 200
		if ip[15] <= 200 {
			continue
		}

		ipStr := ip.String()
		if !p.reverse[ipStr] {
			return ipStr, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique IPv6 after 1000 attempts")
}
