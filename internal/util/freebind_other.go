//go:build !linux

package util

import "syscall"

func freebindControlFunc() func(string, string, syscall.RawConn) error {
	return nil
}
