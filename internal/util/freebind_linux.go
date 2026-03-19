//go:build linux

package util

import "golang.org/x/sys/unix"

func setFreebind(fd uintptr) error {
	errIP := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
	errV6 := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_FREEBIND, 1)
	if errIP != nil && errV6 != nil {
		return errIP
	}
	return nil
}
