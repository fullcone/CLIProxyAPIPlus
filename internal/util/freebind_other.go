//go:build !linux

package util

func setFreebind(fd uintptr) error {
	_ = fd
	return nil
}
