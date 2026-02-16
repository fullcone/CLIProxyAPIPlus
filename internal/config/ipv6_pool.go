// Package config provides configuration management for the CLI Proxy API server.
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
	mu       sync.Mutex
	network  *net.IPNet
	prefixIP net.IP
	ones     int // prefix length in bits
	forward  map[string]string // authID -> IPv6 address string
	reverse  map[string]string // IPv6 address string -> authID
}

var (
	globalIPv6Pool     *IPv6Pool
	globalIPv6PoolOnce sync.Once
)

// GetIPv6Pool returns the global IPv6Pool singleton. If cidr is empty, returns nil.
// The pool is initialized only once; subsequent calls ignore the cidr parameter.
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
	if len(ip.To16()) != net.IPv6len {
		return nil, fmt.Errorf("not an IPv6 CIDR: %s", cidr)
	}
	ones, _ := ipNet.Mask.Size()
	return &IPv6Pool{
		network:  ipNet,
		prefixIP: ip.To16(),
		ones:     ones,
		forward:  make(map[string]string),
		reverse:  make(map[string]string),
	}, nil
}

// Assign returns the IPv6 address for authID. If already assigned, returns the existing one.
// Otherwise generates a new unique random address within the prefix.
func (p *IPv6Pool) Assign(authID string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if addr, ok := p.forward[authID]; ok {
		return addr, nil
	}

	addr, err := p.generateUnique()
	if err != nil {
		return "", err
	}

	p.forward[authID] = addr
	p.reverse[addr] = authID
	return addr, nil
}

// Register records an existing authID -> IPv6 mapping (used at startup to load persisted assignments).
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

// Get returns the IPv6 address assigned to authID, or empty string if not assigned.
func (p *IPv6Pool) Get(authID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.forward[authID]
}

// generateUnique creates a random IPv6 within the prefix that is not yet assigned.
// The prefix bits are preserved; suffix bits are filled with crypto/rand.
// Addresses where the last byte <= 200 are excluded to avoid low-range collisions.
func (p *IPv6Pool) generateUnique() (string, error) {
	const maxAttempts = 1000
	for i := 0; i < maxAttempts; i++ {
		addr, err := p.randomAddr()
		if err != nil {
			return "", err
		}
		addrStr := addr.String()
		if _, taken := p.reverse[addrStr]; !taken {
			return addrStr, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique IPv6 after %d attempts", maxAttempts)
}

func (p *IPv6Pool) randomAddr() (net.IP, error) {
	// Start with a copy of the prefix IP
	result := make(net.IP, net.IPv6len)
	copy(result, p.prefixIP)

	// Generate random bytes for the suffix
	suffixBytes := make([]byte, net.IPv6len)
	if _, err := rand.Read(suffixBytes); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}

	// Apply: keep prefix bits from prefixIP, fill suffix bits from random
	for i := 0; i < net.IPv6len; i++ {
		byteIdx := i
		bitStart := byteIdx * 8
		bitEnd := bitStart + 8

		if bitStart >= p.ones {
			// Entire byte is in suffix range
			result[i] = suffixBytes[i]
		} else if bitEnd > p.ones {
			// Partial byte: keep prefix bits, randomize suffix bits
			prefixBits := p.ones - bitStart
			mask := byte(0xFF << (8 - prefixBits))
			result[i] = (result[i] & mask) | (suffixBytes[i] & ^mask)
		}
		// else: entire byte is in prefix range, keep as-is
	}

	// Exclude addresses where last byte <= 200
	if result[net.IPv6len-1] <= 200 {
		return nil, fmt.Errorf("low-range address, retry")
	}

	return result, nil
}
