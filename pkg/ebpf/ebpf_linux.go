//go:build linux
// +build linux

package ebpf

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

func CheckEbpfFeatures() error {
	err := features.HaveProgramType(ebpf.XDP)
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return fmt.Errorf("kernel doesn't support XDP feature: %w", err)
		}
		return fmt.Errorf("failed to probe kernel XDP feature support: %w", err)
	}

	err = features.HaveMapType(ebpf.Hash)
	if err != nil {
		if errors.Is(err, ebpf.ErrNotSupported) {
			return fmt.Errorf("kernel doesn't support Hash Map type: %w", err)
		}
		return fmt.Errorf("failed to probe kernel Hash Map type support: %w", err)
	}

	return nil
}
