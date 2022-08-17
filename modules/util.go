package modules

import (
	"encoding/binary"
	"net"
)

func inet_ntoa(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, in)
	return ip.String()
}

func inet_btoa(in []byte) string {
	ip := net.IP(in)
	return ip.String()
}
