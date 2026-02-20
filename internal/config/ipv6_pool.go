package config

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
)

// IPv6Pool manages a thread-safe pool of IPv6 addresses assigned to Codex auth IDs.
type IPv6Pool struct {
	mu      sync.Mutex
	network *net.IPNet
	prefix  net.IP
	ones    int // number of prefix bits

	forward map[string]string // authID -> IPv6 string
	reverse map[string]string // IPv6 string -> authID
}

var (
	ipv6PoolOnce     sync.Once
	ipv6PoolInstance *IPv6Pool
)

// GetIPv6Pool returns the global IPv6Pool singleton. If cidr is empty, returns nil.
func GetIPv6Pool(cidr string) *IPv6Pool {
	if cidr == "" {
		return nil
	}
	ipv6PoolOnce.Do(func() {
		pool, err := newIPv6Pool(cidr)
		if err != nil {
			fmt.Printf("WARNING: failed to initialize IPv6 pool from %q: %v\n", cidr, err)
			return
		}
		ipv6PoolInstance = pool
	})
	return ipv6PoolInstance
}

func newIPv6Pool(cidr string) (*IPv6Pool, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	if ip.To16() == nil || ip.To4() != nil {
		return nil, fmt.Errorf("not an IPv6 address: %s", cidr)
	}
	ones, _ := network.Mask.Size()
	prefix := make(net.IP, 16)
	copy(prefix, network.IP.To16())

	return &IPv6Pool{
		network: network,
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

	if existing, ok := p.forward[authID]; ok {
		return existing, nil
	}
	ip, err := p.generateUnique()
	if err != nil {
		return "", err
	}
	ipStr := ip.String()
	p.forward[authID] = ipStr
	p.reverse[ipStr] = authID
	return ipStr, nil
}

// Register records an existing authID -> IPv6 mapping (used at startup for old accounts).
func (p *IPv6Pool) Register(authID, ipv6 string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.forward[authID] = ipv6
	p.reverse[ipv6] = authID
}

// Unregister removes the mapping for authID (used when swapping temp ID for permanent ID).
func (p *IPv6Pool) Unregister(authID string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if ipv6, ok := p.forward[authID]; ok {
		delete(p.reverse, ipv6)
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

// generateUnique creates a random IPv6 within the pool's network that is not yet assigned.
// Must be called with p.mu held.
func (p *IPv6Pool) generateUnique() (net.IP, error) {
	buf := make([]byte, 16)
	for attempts := 0; attempts < 1000; attempts++ {
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("crypto/rand failed: %w", err)
		}

		// Merge: keep prefix bits from p.prefix, use random bits for the rest
		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			ip[i] = (p.prefix[i] & p.network.Mask[i]) | (buf[i] &^ p.network.Mask[i])
		}

		// Exclude low-position addresses that may conflict with gateway/primary addresses:
		// if bytes [8..14] are all zero and byte[15] <= 200, skip.
		isLow := true
		for i := 8; i <= 14; i++ {
			if ip[i] != 0 {
				isLow = false
				break
			}
		}
		if isLow && ip[15] <= 200 {
			continue
		}

		ipStr := ip.String()
		if _, taken := p.reverse[ipStr]; taken {
			continue
		}
		return ip, nil
	}
	return nil, fmt.Errorf("failed to generate unique IPv6 after 1000 attempts")
}
