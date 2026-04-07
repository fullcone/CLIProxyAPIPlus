package util

import (
	"net"
	"net/http"
	"syscall"
	"time"
)

// NewIPv6Transport creates an HTTP transport that binds outgoing connections to
// the given IPv6 address.  It uses IP_FREEBIND (on Linux) so the address can be
// used even when it is not yet assigned to a local interface.
func NewIPv6Transport(ipv6Addr string) *http.Transport {
	dialer := NewIPv6Dialer(ipv6Addr)
	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:  10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// NewIPv6Dialer creates a net.Dialer that binds to the specified IPv6 address
// with IP_FREEBIND support on Linux.
func NewIPv6Dialer(ipv6Addr string) *net.Dialer {
	addr := net.ParseIP(ipv6Addr)
	var localAddr net.Addr
	if addr != nil {
		localAddr = &net.TCPAddr{IP: addr}
	}
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: localAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			return setFreebind(network, address, c)
		},
	}
}
