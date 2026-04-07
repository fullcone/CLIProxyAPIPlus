//go:build !linux

package util

import "syscall"

// setFreebind is a no-op on non-Linux platforms where IP_FREEBIND is unavailable.
func setFreebind(_, _ string, _ syscall.RawConn) error {
	return nil
}
