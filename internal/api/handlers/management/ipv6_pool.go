package management

import (
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
)

// IPv6Pool allocates unique IPv6 addresses from a prefix range, one per owner.
type IPv6Pool struct {
	mu      sync.RWMutex
	prefix  *net.IPNet
	byOwner map[string]string // ownerID -> IPv6 string
	used    map[string]string // IPv6 string -> ownerID
	counter *big.Int          // monotonic allocation counter
}

// NewIPv6Pool creates a pool backed by the given CIDR prefix (e.g. "2001:db8::/48").
func NewIPv6Pool(prefix string) (*IPv6Pool, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil, fmt.Errorf("ipv6 pool: empty prefix")
	}
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, fmt.Errorf("ipv6 pool: invalid prefix %q: %w", prefix, err)
	}
	return &IPv6Pool{
		prefix:  ipNet,
		byOwner: make(map[string]string),
		used:    make(map[string]string),
		counter: big.NewInt(1), // start at 1 to skip network address
	}, nil
}

// Allocate assigns a unique IPv6 address to ownerID. If the owner already has
// one, the existing address is returned.
func (p *IPv6Pool) Allocate(ownerID string) (string, error) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return "", fmt.Errorf("ipv6 pool: empty owner ID")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if addr, ok := p.byOwner[ownerID]; ok {
		return addr, nil
	}

	// Try up to 4096 candidates to skip low-byte addresses.
	const maxAttempts = 4096
	for i := 0; i < maxAttempts; i++ {
		candidate := p.nextAddress()
		if candidate == "" {
			return "", fmt.Errorf("ipv6 pool: prefix exhausted")
		}
		if isLowByteAddress(candidate) {
			continue
		}
		if _, taken := p.used[candidate]; taken {
			continue
		}
		p.byOwner[ownerID] = candidate
		p.used[candidate] = ownerID
		return candidate, nil
	}
	return "", fmt.Errorf("ipv6 pool: failed to allocate after %d attempts", maxAttempts)
}

// Release frees the IPv6 address assigned to ownerID.
func (p *IPv6Pool) Release(ownerID string) {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	addr, ok := p.byOwner[ownerID]
	if !ok {
		return
	}
	delete(p.byOwner, ownerID)
	delete(p.used, addr)
}

// Transfer atomically migrates an IPv6 allocation from one owner to another.
func (p *IPv6Pool) Transfer(fromOwner, toOwner string) {
	fromOwner = strings.TrimSpace(fromOwner)
	toOwner = strings.TrimSpace(toOwner)
	if fromOwner == "" || toOwner == "" || fromOwner == toOwner {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	addr, ok := p.byOwner[fromOwner]
	if !ok {
		return
	}
	delete(p.byOwner, fromOwner)
	p.byOwner[toOwner] = addr
	p.used[addr] = toOwner
}

// GetByOwner returns the IPv6 address assigned to ownerID, or "" if none.
func (p *IPv6Pool) GetByOwner(ownerID string) string {
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.byOwner[ownerID]
}

// nextAddress computes the next candidate from the prefix. Must be called with
// p.mu held.
func (p *IPv6Pool) nextAddress() string {
	base := new(big.Int).SetBytes(p.prefix.IP.To16())
	candidate := new(big.Int).Add(base, p.counter)
	p.counter.Add(p.counter, big.NewInt(1))

	// Verify still within prefix.
	ipBytes := candidate.Bytes()
	if len(ipBytes) > 16 {
		return ""
	}
	ip := make(net.IP, 16)
	copy(ip[16-len(ipBytes):], ipBytes)
	if !p.prefix.Contains(ip) {
		return ""
	}
	return ip.String()
}

// isLowByteAddress returns true when bytes 6-14 (0-indexed) are all zero and
// byte 15 is <= 200.  These addresses can collide with well-known service
// addresses in many network configurations.
func isLowByteAddress(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	ip = ip.To16()
	if ip == nil {
		return false
	}
	for i := 6; i <= 14; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return ip[15] <= 200
}
