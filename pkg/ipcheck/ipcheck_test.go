package ipcheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPCheck(t *testing.T) {
	require.NotPanics(t, func() {
		found := CheckAgainstIPRanges(
			"../../data/test-ips.txt",
			"https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv",
			true,
		)

		require.Equal(t, 3, found)
	})
}
