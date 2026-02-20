package config

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
)

// IPv6Pool manages a thread-safe pool of IPv6 addresses assigned to auth IDs.
// It generates unique random addresses within a given CIDR prefix and maintains
// bidirectional mappings to prevent collisions.
type IPv6Pool struct {
	mu      sync.Mutex
	network *net.IPNet
	ones    int // prefix length in bits

	forward map[string]net.IP // authID -> IPv6
	reverse map[string]string // IPv6 string -> authID
}

var (
	globalIPv6Pool     *IPv6Pool
	globalIPv6PoolOnce sync.Once
)

// GetIPv6Pool returns the global IPv6Pool singleton. If cidr is empty, returns nil.
// The pool is initialised exactly once; subsequent calls ignore the cidr argument.
func GetIPv6Pool(cidr string) *IPv6Pool {
	if cidr == "" {
		return nil
	}
	globalIPv6PoolOnce.Do(func() {
		pool, err := newIPv6Pool(cidr)
		if err != nil {
			fmt.Printf("ipv6 pool: failed to initialise from %s: %v\n", cidr, err)
			return
		}
		globalIPv6Pool = pool
	})
	return globalIPv6Pool
}

func newIPv6Pool(cidr string) (*IPv6Pool, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	if len(ip.To16()) != net.IPv6len {
		return nil, fmt.Errorf("not an IPv6 CIDR: %s", cidr)
	}
	ones, _ := ipNet.Mask.Size()
	return &IPv6Pool{
		network: ipNet,
		ones:    ones,
		forward: make(map[string]net.IP),
		reverse: make(map[string]string),
	}, nil
}

// Assign returns the IPv6 address for authID. If none exists, a new unique
// random address is generated within the pool's prefix.
func (p *IPv6Pool) Assign(authID string) (net.IP, error) {
	if p == nil {
		return nil, fmt.Errorf("ipv6 pool is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ip, ok := p.forward[authID]; ok {
		return ip, nil
	}
	ip, err := p.generateUnique()
	if err != nil {
		return nil, err
	}
	p.forward[authID] = ip
	p.reverse[ip.String()] = authID
	return ip, nil
}

// Register records an existing authID ↔ IPv6 mapping (used at startup to reload
// persisted assignments). It writes both forward and reverse maps.
func (p *IPv6Pool) Register(authID string, ip net.IP) {
	if p == nil || ip == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.forward[authID] = ip
	p.reverse[ip.String()] = authID
}

// Unregister removes the mapping for authID (used when replacing a temporary ID
// with a permanent one).
func (p *IPv6Pool) Unregister(authID string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if ip, ok := p.forward[authID]; ok {
		delete(p.reverse, ip.String())
	}
	delete(p.forward, authID)
}

// Get returns the assigned IPv6 for authID, or nil if none exists.
func (p *IPv6Pool) Get(authID string) net.IP {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.forward[authID]
}

// generateUnique creates a random IPv6 within the prefix that is not yet assigned
// and does not collide with low gateway addresses. Caller must hold p.mu.
func (p *IPv6Pool) generateUnique() (net.IP, error) {
	prefixBytes := p.ones / 8 // byte index where random bits start

	for attempts := 0; attempts < 1000; attempts++ {
		ip := make(net.IP, net.IPv6len)
		copy(ip, p.network.IP.To16())

		// Fill random bytes from the prefix boundary onward.
		suffix := make([]byte, net.IPv6len-prefixBytes)
		if _, err := rand.Read(suffix); err != nil {
			return nil, fmt.Errorf("crypto/rand: %w", err)
		}

		// If prefix is not byte-aligned, preserve the prefix bits in the boundary byte.
		if p.ones%8 != 0 {
			mask := byte(0xFF << (8 - p.ones%8))
			suffix[0] = (ip[prefixBytes] & mask) | (suffix[0] & ^mask)
		}
		copy(ip[prefixBytes:], suffix)

		// Exclude low addresses that may conflict with gateway/router addresses.
		// Check bytes from prefixBytes to byte[14]: if all zero and byte[15] <= 200, skip.
		isLow := true
		for i := prefixBytes; i < 15; i++ {
			if ip[i] != 0 {
				isLow = false
				break
			}
		}
		if isLow && ip[15] <= 200 {
			continue
		}

		if !p.network.Contains(ip) {
			continue
		}
		if _, taken := p.reverse[ip.String()]; taken {
			continue
		}
		return ip, nil
	}
	return nil, fmt.Errorf("failed to generate unique IPv6 after 1000 attempts")
}
