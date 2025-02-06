package wgserver

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"net"
)

var testExternalIPv4 = net.ParseIP("1.1.1.1")
var testExternalIPv6 = net.ParseIP("2606:4700:4700::1111")

func GetExternalLink(family int) (netlink.Link, net.IP, error) {
	var testIP net.IP
	switch family {
	case unix.AF_INET:
		testIP = testExternalIPv4
	case unix.AF_INET6:
		testIP = testExternalIPv6
	default:
		return nil, nil, fmt.Errorf("unknown network family: %d", family)
	}
	route, err := netlink.RouteGet(testIP)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get default route: %w", err)
	}
	if len(route) == 0 {
		return nil, nil, fmt.Errorf("failed to get default route: empty")
	}

	link, err := netlink.LinkByIndex(route[0].LinkIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get inderface by index: %w", err)
	}

	return link, route[0].Src, nil
}

func GetDefaultIPs() (ip4 net.IP, ip6 net.IP, err error) {
	route4, err := netlink.RouteGet(testExternalIPv4)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get default route: %w", err)
	}

	if len(route4) > 0 {
		ip4 = route4[0].Src
	}

	route6, err := netlink.RouteGet(testExternalIPv6)
	if err == nil {
		if len(route6) > 0 {
			ip6 = route6[0].Src
		}
	}

	if ip4 == nil {
		return nil, nil, fmt.Errorf("failed to get default route: empty")
	}

	return ip4, ip6, nil
}
