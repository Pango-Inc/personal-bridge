package nic

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNICPool(t *testing.T) {
	nicPool := NewNICPool()

	nic1, err := nicPool.GetNIC()
	require.NoError(t, err)
	require.Equal(t, uint32(0), nic1)

	nic2, err := nicPool.GetNIC()
	require.NoError(t, err)
	require.Equal(t, uint32(1), nic2)

	nicPool.FreeNIC(nic1)

	nic3, err := nicPool.GetNIC()
	require.NoError(t, err)
	require.Equal(t, uint32(0), nic3)

	nic4, err := nicPool.GetNIC()
	require.NoError(t, err)
	require.Equal(t, uint32(2), nic4)
}
