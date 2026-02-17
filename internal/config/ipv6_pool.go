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
	prefix  net.IP // 16-byte canonical prefix
	ones    int    // prefix length in bits

	forward map[string]string // authID -> IPv6 string
	reverse map[string]string // IPv6 string -> authID
}

var (
	ipv6PoolOnce     sync.Once
	ipv6PoolInstance *IPv6Pool
)

// GetIPv6Pool returns the global IPv6Pool singleton. If cidr is empty, returns nil.
// The pool is initialized once; subsequent calls ignore the cidr parameter.
func GetIPv6Pool(cidr string) *IPv6Pool {
	if cidr == "" {
		return ipv6PoolInstance
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
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	if ip.To16() == nil || ip.To4() != nil {
		return nil, fmt.Errorf("%q is not an IPv6 address", cidr)
	}
	ones, _ := ipNet.Mask.Size()
	prefix := make(net.IP, 16)
	copy(prefix, ipNet.IP.To16())

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
	if p == nil {
		return "", fmt.Errorf("ipv6 pool is nil")
	}
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

// Register records an existing authID -> IPv6 mapping (used at startup to reload persisted assignments).
func (p *IPv6Pool) Register(authID, ipv6 string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.forward[authID] = ipv6
	p.reverse[ipv6] = authID
}

// Unregister removes the mapping for authID, freeing the address for reuse.
func (p *IPv6Pool) Unregister(authID string) {
	if p == nil {
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

// generateUnique creates a random IPv6 within the pool's network that is not yet assigned.
// Caller must hold p.mu.
func (p *IPv6Pool) generateUnique() (string, error) {
	buf := make([]byte, 16)
	for attempts := 0; attempts < 1000; attempts++ {
		// Start from the prefix
		copy(buf, p.prefix)

		// Fill random bytes for the host portion
		randBytes := make([]byte, 16)
		if _, err := rand.Read(randBytes); err != nil {
			return "", fmt.Errorf("crypto/rand failed: %w", err)
		}

		// Merge: keep prefix bits, randomize host bits
		for i := 0; i < 16; i++ {
			maskByte := p.network.Mask[i]
			buf[i] = (p.prefix[i] & maskByte) | (randBytes[i] & ^maskByte)
		}

		// Exclude addresses where the lower 64 bits represent a value <= 200
		// i.e., bytes [8..14] are all zero and byte[15] <= 200
		if buf[8] == 0 && buf[9] == 0 && buf[10] == 0 && buf[11] == 0 &&
			buf[12] == 0 && buf[13] == 0 && buf[14] == 0 && buf[15] <= 200 {
			continue
		}

		ip := net.IP(buf)
		addr := ip.String()
		if _, taken := p.reverse[addr]; taken {
			continue
		}
		return addr, nil
	}
	return "", fmt.Errorf("failed to generate unique IPv6 after 1000 attempts")
}
