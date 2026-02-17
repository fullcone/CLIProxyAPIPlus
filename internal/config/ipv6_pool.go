package config

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
)

// IPv6Pool manages per-account IPv6 address allocation from a CIDR prefix.
// It is thread-safe and ensures each authID gets a unique, stable address.
type IPv6Pool struct {
	mu      sync.Mutex
	network *net.IPNet
	prefix  net.IP
	ones    int // prefix length in bits

	forward map[string]string // authID -> IPv6 string
	reverse map[string]string // IPv6 string -> authID
}

var (
	ipv6PoolOnce     sync.Once
	ipv6PoolInstance *IPv6Pool
)

// GetIPv6Pool returns the global IPv6Pool singleton.
// If cidr is empty, returns nil. Initialised once; subsequent calls ignore cidr.
func GetIPv6Pool(cidr string) *IPv6Pool {
	if cidr == "" {
		return ipv6PoolInstance // may be nil
	}
	ipv6PoolOnce.Do(func() {
		pool, err := newIPv6Pool(cidr)
		if err != nil {
			fmt.Printf("ipv6 pool init error: %v\n", err)
			return
		}
		ipv6PoolInstance = pool
	})
	return ipv6PoolInstance
}

func newIPv6Pool(cidr string) (*IPv6Pool, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid IPv6 CIDR %q: %w", cidr, err)
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("expected IPv6 CIDR, got %d-bit network", bits)
	}
	prefix := ip.To16()
	if prefix == nil {
		prefix = ipNet.IP.To16()
	}
	return &IPv6Pool{
		network: ipNet,
		prefix:  prefix,
		ones:    ones,
		forward: make(map[string]string),
		reverse: make(map[string]string),
	}, nil
}

// Assign returns the IPv6 address for authID, allocating a new one if needed.
func (p *IPv6Pool) Assign(authID string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("ipv6 pool is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if addr, ok := p.forward[authID]; ok {
		return addr, nil
	}
	return p.generateUnique(authID)
}

// Register records an existing authID -> IPv6 mapping (used at startup for persisted accounts).
func (p *IPv6Pool) Register(authID, ipv6 string) {
	if p == nil || authID == "" || ipv6 == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.forward[authID] = ipv6
	p.reverse[ipv6] = authID
}

// Unregister removes the mapping for authID (used when swapping temp ID for permanent ID).
func (p *IPv6Pool) Unregister(authID string) {
	if p == nil || authID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if addr, ok := p.forward[authID]; ok {
		delete(p.reverse, addr)
		delete(p.forward, authID)
	}
}

// Get returns the IPv6 address for authID, or empty string if not assigned.
func (p *IPv6Pool) Get(authID string) string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.forward[authID]
}

// generateUnique creates a random IPv6 within the prefix that is not yet allocated.
// Must be called with p.mu held.
func (p *IPv6Pool) generateUnique(authID string) (string, error) {
	prefixBytes := len(p.network.Mask) // 16
	for attempts := 0; attempts < 1000; attempts++ {
		addr := make(net.IP, prefixBytes)
		copy(addr, p.prefix)

		// Fill random bytes for the host portion
		randomBytes := make([]byte, prefixBytes)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("crypto/rand failed: %w", err)
		}

		// Apply: keep prefix bits from p.prefix, fill suffix bits from random
		for i := 0; i < prefixBytes; i++ {
			maskByte := p.network.Mask[i]
			addr[i] = (p.prefix[i] & maskByte) | (randomBytes[i] & ^maskByte)
		}

		// Exclude low-value addresses that may conflict with gateway/primary
		if isLowAddress(addr) {
			continue
		}

		addrStr := addr.String()
		if _, taken := p.reverse[addrStr]; taken {
			continue
		}

		p.forward[authID] = addrStr
		p.reverse[addrStr] = authID
		return addrStr, nil
	}
	return "", fmt.Errorf("failed to generate unique IPv6 after 1000 attempts")
}

// isLowAddress returns true if bytes [8..14] are all zero and byte[15] <= 200.
// These addresses (like ::1, ::2, ::c8) may conflict with gateway/primary addresses.
func isLowAddress(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return false
	}
	for i := 8; i <= 14; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return ip[15] <= 200
}
