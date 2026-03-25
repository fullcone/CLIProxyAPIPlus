//go:build linux

package util

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func freebindControlFunc() func(string, string, syscall.RawConn) error {
	return func(_ string, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
