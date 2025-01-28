//go:build !linux
// +build !linux

package ebpf

import "fmt"

func CheckEbpfFeatures() error {
	return fmt.Errorf("ebpf is not supported on this platform")
}
