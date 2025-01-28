package wgserver

import (
	"errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"log/slog"
	"net"
	"vpnlite/pkg/ebpf"
)

type ProfileHandle struct {
	WGPeer *wgtypes.PeerConfig
	IP4    net.IP
	IP6    net.IP
	handle *ebpf.EbpfHandle
}

func (s *ProfileHandle) SetupForwarding(ip4, ip6 net.IP, link uint32) error {
	if s.IP4 != nil && ip4 != nil && ip4.To4() != nil {
		slog.Debug("server: set src rule", slog.Any("from", s.IP4),
			slog.Any("to", ip4), slog.Any("link", link))
		err := s.handle.SetSrcRule(s.IP4, ip4, link)
		if err != nil {
			slog.Error("server: set src rule",
				slog.Any("ip4", s.IP4),
				slog.Any("forward_ip4", ip4),
				slog.Any("forward_link", link),
				slog.Any("error", err))
		}
	}

	if s.IP6 != nil && ip6 != nil && ip6.To4() == nil {
		slog.Debug("server: set src rule", slog.Any("from", s.IP6),
			slog.Any("to", ip6), slog.Any("link", link))
		err := s.handle.SetSrcRule(s.IP6, ip6, link)
		if err != nil {
			slog.Error("server: set src rule",
				slog.Any("ip6", s.IP6),
				slog.Any("forward_ip6", ip6),
				slog.Any("forward_link", link),
				slog.Any("error", err))
		}
	}

	return nil
}

func (s *ProfileHandle) GetStats() (uint64, uint64) {
	var counterPackets, counterBytes uint64

	var err error
	var rule ebpf.RuleValue
	if s.IP4 != nil {
		err = s.handle.SrcRules.Lookup(&ebpf.RuleKey{IP: s.IP4}, &rule)
		if err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				slog.Error("failed to lookup src rule", slog.Any("err", err))
			}
		} else {
			counterPackets += rule.CounterPackets
			counterBytes += rule.CounterBytes
		}
	}

	if s.IP6 != nil {
		err = s.handle.SrcRules.Lookup(&ebpf.RuleKey{IP: s.IP6}, &rule)
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
