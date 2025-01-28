package wgclient

import (
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"log/slog"
	"net"
	"vpnlite/pkg/ebpf"
)

type ProfileHandle struct {
	id         uint64
	nicId      uint32
	nicName    string
	privateKey wgtypes.Key
	link       netlink.Link
	handle     *ebpf.EbpfHandle
	ip4        net.IP
	ip6        net.IP
}

func (s *ProfileHandle) SetupForwarding(ip4 net.IP, ip6 net.IP, link uint32) error {
	var err error

	if ip4 != nil && s.ip4 != nil {
		slog.Debug("client: set dst rule", slog.Any("from", s.ip4), slog.Any("to", ip4),
			slog.Any("link", link))
		err = s.handle.SetDstRule(s.ip4, ip4, link)
		if err != nil {
			return fmt.Errorf("set dst replace: %v", err)
		}
	}

	if ip6 != nil && s.ip6 != nil {
		slog.Debug("client: set dst rule", slog.Any("from", s.ip6), slog.Any("to", ip6),
			slog.Any("link", link))
		err = s.handle.SetDstRule(s.ip6, ip6, link)
		if err != nil {
			return fmt.Errorf("set dst replace: %v", err)
		}
	}

	return nil
}

func (s *ProfileHandle) DumpMaps() {
	slog.Info("client: dump maps", slog.Int("ifindex", s.link.Attrs().Index))

	var k ebpf.RuleKey
	var v ebpf.RuleValue
	it := s.handle.SrcRules.Iterate()
	for it.Next(&k, &v) {
		slog.Info("client: src map entry",
			slog.String("key", k.IP.String()),
			slog.String("value_ip", v.Replace.String()),
			slog.Int("value_ifindex", int(v.Ifindex)))
	}

	it = s.handle.DstRules.Iterate()
	for it.Next(&k, &v) {
		slog.Info("client: dst map entry",
			slog.String("key", k.IP.String()),
			slog.String("value_ip", v.Replace.String()),
			slog.Int("value_ifindex", int(v.Ifindex)))
	}
}

func (s *ProfileHandle) GetStats() (uint64, uint64) {
	var counterPackets, counterBytes uint64

	var err error
	var rule ebpf.RuleValue
	if s.ip4 != nil {
		err = s.handle.DstRules.Lookup(&ebpf.RuleKey{IP: s.ip4}, &rule)
		if err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				slog.Error("failed to lookup src rule", slog.Any("err", err))
			}
		} else {
			counterPackets += rule.CounterPackets
			counterBytes += rule.CounterBytes
		}
	}

	if s.ip6 != nil {
		err = s.handle.DstRules.Lookup(&ebpf.RuleKey{IP: s.ip6}, &rule)
		if err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				slog.Error("failed to lookup src rule", slog.Any("err", err))
			}
		} else {
			counterPackets += rule.CounterPackets
			counterBytes += rule.CounterBytes
		}
	}

	return counterPackets, counterBytes
}

func (s *ProfileHandle) GetLink() uint32 {
	return uint32(s.link.Attrs().Index)
}
