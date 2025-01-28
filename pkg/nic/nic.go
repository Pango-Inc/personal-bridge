package nic

import (
	"fmt"
	"sync"
)

type NICPool struct {
	lock       sync.Mutex
	nicCounter uint32
	nicFree    map[uint32]bool
	nicUsed    map[uint32]bool
}

func NewNICPool() *NICPool {
	return &NICPool{
		nicFree: make(map[uint32]bool),
		nicUsed: make(map[uint32]bool),
	}
}

func (s *NICPool) GetNIC() (uint32, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if len(s.nicFree) == 0 {
		// No free NICs, allocate a new one
		nicId := s.nicCounter
		s.nicCounter++

		// Mark the NIC as used
		s.nicUsed[nicId] = true
		return nicId, nil
	}

	for k := range s.nicFree {
		delete(s.nicFree, k)
		s.nicUsed[k] = true
		return k, nil
	}

	return 0, fmt.Errorf("nic pool exhausted")
}

func (s *NICPool) FreeNIC(nicId uint32) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, ok := s.nicUsed[nicId]; !ok {
		return
	}

	delete(s.nicUsed, nicId)
	s.nicFree[nicId] = true
}
