//go:build linux

package util

import (
	"syscall"
)

// setFreebind sets IP_FREEBIND on the socket so that the kernel allows binding
// to an IPv6 address that is not (yet) assigned to a local interface.
func setFreebind(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_FREEBIND, 1)
	})
	if err != nil {
		return err
	}
	return opErr
}
