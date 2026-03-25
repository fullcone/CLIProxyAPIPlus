package util

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// NewIPv6Transport returns a direct HTTP transport that binds outbound sockets
// to the supplied IPv6 source address and forces IPv6 TCP dialing.
func NewIPv6Transport(raw string) (*http.Transport, error) {
	dialer, err := NewIPv6Dialer(raw)
	if err != nil {
		return nil, err
	}

	var transport *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
		transport = base.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, _ string, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp6", addr)
	}
	return transport, nil
}

// NewIPv6Dialer returns a net.Dialer configured to bind the supplied IPv6
// source address with IP_FREEBIND when supported by the current platform.
func NewIPv6Dialer(raw string) (*net.Dialer, error) {
	addr, err := parseIPv6SourceAddr(raw)
	if err != nil {
		return nil, err
	}
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IP(addr.AsSlice())},
		Control:   freebindControlFunc(),
	}, nil
}

func parseIPv6SourceAddr(raw string) (netip.Addr, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return netip.Addr{}, fmt.Errorf("empty IPv6 source address")
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IPv6 source address %q: %w", trimmed, err)
	}
	if !addr.Is6() {
		return netip.Addr{}, fmt.Errorf("source address %q is not IPv6", trimmed)
	}
	return addr.Unmap(), nil
}
