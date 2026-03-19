package util

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// NewIPv6Dialer builds a dialer that binds to the provided IPv6 address
// and enables IP_FREEBIND when supported.
func NewIPv6Dialer(ipv6Addr string, timeout, keepAlive time.Duration) (*net.Dialer, error) {
	ip, err := parseIPv6(ipv6Addr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: keepAlive,
		LocalAddr: &net.TCPAddr{IP: ip},
	}
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		return enableFreebind(c)
	}
	return dialer, nil
}

// NewIPv6Transport builds an HTTP transport that dials using tcp6 with
// a fixed local IPv6 address and freebind enabled when supported.
func NewIPv6Transport(ipv6Addr string) (*http.Transport, error) {
	dialer, err := NewIPv6Dialer(ipv6Addr, 30*time.Second, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp6", addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}, nil
}

func parseIPv6(ipv6Addr string) (net.IP, error) {
	ipv6Addr = strings.TrimSpace(ipv6Addr)
	if ipv6Addr == "" {
		return nil, fmt.Errorf("ipv6 address is empty")
	}
	ip := net.ParseIP(ipv6Addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid ipv6 address %q", ipv6Addr)
	}
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		return nil, fmt.Errorf("invalid ipv6 address %q", ipv6Addr)
	}
	return ip, nil
}

func enableFreebind(c syscall.RawConn) error {
	if c == nil {
		return nil
	}
	var ctrlErr error
	if err := c.Control(func(fd uintptr) {
		ctrlErr = setFreebind(fd)
	}); err != nil {
		if ctrlErr == nil {
			ctrlErr = err
		}
	}
	return ctrlErr
}
