// This file has been modified to use IP ranges instead of time.Time.
// The original one can be found here: https://github.com/obitech/go-trees
package interval

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/pkg/errors"
)

// Interval marks an IP range.
type Interval struct {
	IPRangeMin string
	IPRangeMax string
	low        uint32
	high       uint32
}

// NewInterval returns a new Interval or an error if end is before start.
func NewInterval(ipRangeMin, ipRangeMax string) (Interval, error) {
	min := ip2Long(ipRangeMin)
	max := ip2Long(ipRangeMax)

	if min > max {
		return Interval{}, errors.Errorf("invalid ip range: range max before min [%s - %s]", ipRangeMin, ipRangeMax)
	}

	return Interval{
		IPRangeMin: ipRangeMin,
		IPRangeMax: ipRangeMax,
		low:        min,
		high:       max,
	}, nil
}

// Start returns the lower bound of the interval.
func (i Interval) Start() uint32 {
	return i.low
}

// Stop returns the upper bound of the interval.
func (i Interval) Stop() uint32 {
	return i.high
}

func (i Interval) less(x Interval) bool {
	return i.low < x.low || i.low == x.low && i.high < x.high
}

func (i Interval) overlaps(x Interval) bool {
	return i.low <= x.high && i.high >= x.low
}

func (i Interval) String() string {
	return fmt.Sprintf("[%d - %d]", i.low, i.high)
}

func ip2Long(ip string) uint32 {
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	return long
}
