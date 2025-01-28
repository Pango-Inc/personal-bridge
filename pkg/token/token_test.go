package token

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestToken(t *testing.T) {
	testuserToken, err := NewToken("testuser")
	require.NoError(t, err)

	claims, err := ParseToken(testuserToken)
	require.NoError(t, err)

	require.Equal(t, "testuser", claims.Subject)
}
