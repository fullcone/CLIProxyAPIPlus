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
	prefix  net.IP // 16-byte network address
	ones    int    // prefix length

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
			fmt.Printf("WARNING: failed to initialize IPv6 pool from %q: %v\n", cidr, err)
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
	prefix := ip.To16()
	if prefix == nil {
		return nil, fmt.Errorf("not a valid IPv6 address: %s", cidr)
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		return nil, fmt.Errorf("not an IPv6 CIDR: %s", cidr)
	}
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

	if addr, ok := p.forward[authID]; ok {
		return addr, nil
	}
	return p.generateUnique(authID)
}

// Register records an existing authID -> IPv6 mapping (used at startup to load persisted addresses).
func (p *IPv6Pool) Register(authID, ipv6 string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.forward[authID] = ipv6
	p.reverse[ipv6] = authID
}

// Unregister removes the mapping for authID (used when replacing a temporary ID with a permanent one).
func (p *IPv6Pool) Unregister(authID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if addr, ok := p.forward[authID]; ok {
		delete(p.reverse, addr)
		delete(p.forward, authID)
	}
}

// Get returns the IPv6 address for authID, or empty string if not assigned.
func (p *IPv6Pool) Get(authID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.forward[authID]
}

// generateUnique creates a random IPv6 within the prefix that doesn't collide with existing assignments.
// Must be called with p.mu held.
func (p *IPv6Pool) generateUnique(authID string) (string, error) {
	for attempts := 0; attempts < 1000; attempts++ {
		ip := make(net.IP, 16)
		copy(ip, p.prefix)

		// Fill random bytes into the host portion
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("crypto/rand failed: %w", err)
		}

		// Preserve prefix bits, randomize host bits
		for i := 0; i < 16; i++ {
			bitsInByte := p.ones - i*8
			if bitsInByte >= 8 {
				// Entire byte is prefix — keep it
				continue
			} else if bitsInByte <= 0 {
				// Entire byte is host — use random
				ip[i] = randomBytes[i]
			} else {
				// Partial: keep top bitsInByte bits from prefix, rest from random
				mask := byte(0xFF << (8 - bitsInByte))
				ip[i] = (ip[i] & mask) | (randomBytes[i] & ^mask)
			}
		}

		// Exclude low addresses that may conflict with gateway/primary:
		// If bytes [8..14] are all zero and byte[15] <= 200, skip.
		isLow := true
		for b := 8; b <= 14; b++ {
			if ip[b] != 0 {
				isLow = false
				break
			}
		}
		if isLow && ip[15] <= 200 {
			continue
		}

		addr := ip.String()
		if _, taken := p.reverse[addr]; taken {
			continue
		}

		p.forward[authID] = addr
		p.reverse[addr] = authID
		return addr, nil
	}
	return "", fmt.Errorf("failed to generate unique IPv6 after 1000 attempts")
}
