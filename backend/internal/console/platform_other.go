//go:build !linux

package console

import (
	"net"
	"os"
)

func syncDirectory(string) error                     { return nil }
func peerAllowed(*net.UnixConn, uint32) bool         { return false }
func fileIdentity(info os.FileInfo) (uint64, uint64) { return 0, uint64(info.ModTime().UnixNano()) }
