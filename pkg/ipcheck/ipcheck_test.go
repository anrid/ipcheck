package ipcheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPCheck(t *testing.T) {
	found, err := CheckAgainstIPRanges(
		"../../data/test-ips.txt",
		"https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv",
		"",
		true,
	)
	require.NoError(t, err)
	require.Equal(t, 3, found)
}
