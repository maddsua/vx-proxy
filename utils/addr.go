package utils

import (
	"net"
)

func GetLocalDialAddrTCP(addr net.Addr) *net.TCPAddr {

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return nil
	}

	if tcpAddr.IP.IsLoopback() {
		return nil
	}

	return &net.TCPAddr{
		IP: tcpAddr.IP,
	}
}
