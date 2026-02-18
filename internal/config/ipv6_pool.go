package config

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
)

// IPv6Pool manages a thread-safe pool of IPv6 addresses assigned to auth IDs.
// It ensures each auth ID gets a unique, deterministic IPv6 address from a given CIDR prefix.
type IPv6Pool struct {
	mu      sync.Mutex
	network *net.IPNet
	prefix  net.IP
	ones    int // number of prefix bits

	forward map[string]string // authID -> IPv6 string
	reverse map[string]string // IPv6 string -> authID
}

var (
	globalIPv6Pool     *IPv6Pool
	globalIPv6PoolOnce sync.Once
)

// GetIPv6Pool returns the global IPv6Pool singleton. If cidr is empty, returns nil.
// The pool is initialized once; subsequent calls ignore the cidr parameter.
func GetIPv6Pool(cidr string) *IPv6Pool {
	if cidr == "" {
		return nil
	}
	globalIPv6PoolOnce.Do(func() {
		pool, err := newIPv6Pool(cidr)
		if err != nil {
			fmt.Printf("WARNING: failed to initialize IPv6 pool from CIDR %q: %v\n", cidr, err)
			return
		}
		globalIPv6Pool = pool
	})
	return globalIPv6Pool
}

func newIPv6Pool(cidr string) (*IPv6Pool, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR: %w", err)
	}
	if len(ip.To16()) != 16 {
		return nil, fmt.Errorf("not a valid IPv6 address: %s", cidr)
	}
	ones, _ := ipNet.Mask.Size()
	prefix := ip.To16()

	return &IPv6Pool{
		network: ipNet,
		prefix:  prefix,
		ones:    ones,
		forward: make(map[string]string),
		reverse: make(map[string]string),
	}, nil
}

// Assign returns the IPv6 address for authID. If not yet assigned, generates a new unique one.
func (p *IPv6Pool) Assign(authID string) (string, error) {
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

// Register records an existing authID -> IPv6 mapping (used at startup to load persisted assignments).
func (p *IPv6Pool) Register(authID string, ipv6 string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.forward[authID] = ipv6
	p.reverse[ipv6] = authID
}

// Unregister removes the mapping for authID (used when replacing a temporary ID with a permanent one).
func (p *IPv6Pool) Unregister(authID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ipv6, ok := p.forward[authID]; ok {
		delete(p.reverse, ipv6)
		delete(p.forward, authID)
	}
}

// Get returns the IPv6 address for authID, or empty string if not assigned.
func (p *IPv6Pool) Get(authID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.forward[authID]
}

// generateUnique creates a random IPv6 within the pool's network that hasn't been assigned yet.
// Must be called with p.mu held.
func (p *IPv6Pool) generateUnique() (net.IP, error) {
	for attempts := 0; attempts < 1000; attempts++ {
		ip := make(net.IP, 16)
		copy(ip, p.prefix)

		// Fill random bytes for the host portion
		var randomBytes [16]byte
		if _, err := rand.Read(randomBytes[:]); err != nil {
			return nil, fmt.Errorf("crypto/rand: %w", err)
		}

		// Merge: keep prefix bits from p.prefix, fill remaining with random
		prefixBytes := p.ones / 8
		prefixBits := p.ones % 8

		// Full random bytes start after the prefix
		for i := prefixBytes + 1; i < 16; i++ {
			ip[i] = randomBytes[i]
		}
		// Handle the partial byte at the boundary
		if prefixBits > 0 && prefixBytes < 16 {
			mask := byte(0xFF << (8 - prefixBits))
			ip[prefixBytes] = (p.prefix[prefixBytes] & mask) | (randomBytes[prefixBytes] & ^mask)
		} else if prefixBytes < 16 {
			ip[prefixBytes] = randomBytes[prefixBytes]
		}

		// Exclude low-address range that may conflict with gateway/primary addresses:
		// If bytes [8..14] are all zero and byte[15] <= 200, skip.
		isLow := true
		for i := 8; i < 15; i++ {
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
