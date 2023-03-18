package iputil

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/pkg/errors"
)

func IP2Long(ip string) uint32 {
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	return long
}

func Long2IP(n uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip.To4().String()
}

func CIDRToIPRange(cidr string) (startIP, endIP string, err error) {
	// Convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", errors.Wrapf(err, "could not convert CIDR '%s' to IP range", cidr)
	}

	// Convert IPNet struct mask and address to uint32.
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)

	// Find the start IP address.
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// Find the end IP address.
	end := (start & mask) | (mask ^ 0xffffffff)

	startIP = Long2IP(start)
	endIP = Long2IP(end)

	return
}
