package ippool

import (
	"net"
	"sync"
)

type IPPool struct {
	name     string
	initOnce sync.Once
	lock     sync.Mutex
	subnet   *net.IPNet
	iter     net.IP
	busy     map[string]struct{}
	free     map[string]struct{}
}

// New returns ip pool.
func New(name, subnetCidr string) (*IPPool, error) {
	_, ipnet, err := net.ParseCIDR(subnetCidr)
	if err != nil {
		return nil, err
	}
	iter := CopyIP(ipnet.IP)
	// skip zero and one IPs
	IncIPInPlace(iter)
	IncIPInPlace(iter)

	return &IPPool{
		name:   name,
		subnet: ipnet,
		iter:   iter,
		free:   map[string]struct{}{},
		busy:   map[string]struct{}{},
	}, nil
}

func (s *IPPool) Subnet() *net.IPNet {
	return s.subnet
}

func (s *IPPool) First() net.IP {
	ip := CopyIP(s.subnet.IP)
	IncIPInPlace(ip)
	return ip
}

// AcquireIP acquires ip in pull
func (s *IPPool) SetAcquired(ip net.IP) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.free, ip.String())
	s.busy[ip.String()] = struct{}{}
}

func (s *IPPool) Acquire() net.IP {
	s.lock.Lock()
	defer s.lock.Unlock()

	for ip := range s.free {
		delete(s.free, ip)
		s.busy[ip] = struct{}{}
		return net.ParseIP(ip)
	}

	// skip all busy IP, it can be set busy in SetAcquired
	for {
		if _, ok := s.busy[s.iter.String()]; ok {
			IncIPInPlace(s.iter)
			continue
		}
		break
	}

	if !s.subnet.Contains(s.iter) {
		// pool exhausted, all IPs are busy
		return nil
	}

	ip := CopyIP(s.iter)
	IncIPInPlace(s.iter)

	s.busy[ip.String()] = struct{}{}
	return ip
}

func (s *IPPool) Release(ip net.IP) {
	ips := ip.String()

	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.busy, ips)
	s.free[ips] = struct{}{}
}

func IncIPInPlace(ip net.IP) net.IP {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}

	return ip
}

func IncIP(ip net.IP) net.IP {
	nip := CopyIP(ip)
	IncIPInPlace(nip)
	return nip
}

func CopyIP(ip net.IP) net.IP {
	cip := make(net.IP, len(ip))
	copy(cip, ip)
	return cip
}
