package interval

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIntervalTree(t *testing.T) {
	r := require.New(t)

	tree := NewIntervalTree()

	r1, err := NewInterval("10.10.10.0", "10.20.30.40")
	if err != nil {
		panic(err)
	}

	r2, err := NewInterval("20.20.20.2", "20.20.20.2")
	if err != nil {
		panic(err)
	}

	r3, err := NewInterval("255.255.255.250", "255.255.255.255")
	if err != nil {
		panic(err)
	}

	r4, err := NewInterval("20.20.20.2", "20.20.20.3")
	if err != nil {
		panic(err)
	}

	tree.Upsert(r1, "Azure")
	tree.Upsert(r2, "GCP")
	tree.Upsert(r3, "AWS")
	tree.Upsert(r4, "GCP")

	tests := []struct {
		IP            string
		ShouldBeFound bool
	}{
		{"10.10.10.0", true},
		{"20.20.20.2", true},
		{"255.255.255.255", true},
		{"30.30.30.30", false},
		{"10.20.30.40", true},
		{"10.20.30.41", false},
		{"255.255.255.250", true},
		{"255.255.255.249", false},
	}

	for _, t := range tests {
		search, err := NewInterval(t.IP, t.IP)
		r.NoError(err)

		re, err := tree.FindFirstOverlapping(search)
		if err != nil {
			if t.ShouldBeFound {
				r.Failf("should have found ip", "%s", t.IP)
			}
		} else {
			if !t.ShouldBeFound {
				r.Failf("should not have found ip", "%s  [%s - %s] %s", t.IP, re.Interval.IPRangeMin, re.Interval.IPRangeMax, re.Payload)
			}
		}

		res, err := tree.FindAllOverlapping(search)
		if err != nil {
			if t.ShouldBeFound {
				r.Failf("should have found ip", "%s", t.IP)
			}
		} else {
			if !t.ShouldBeFound {
				for _, re := range res {
					fmt.Printf("should not have found ip: %s  [%s - %s] %s\n", t.IP, re.Interval.IPRangeMin, re.Interval.IPRangeMax, re.Payload)
				}
				r.Fail("we're screwed")
			}
		}
	}
}
