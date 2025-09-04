package utils

import (
	"net"
	"time"
)

func NewTcpDialer(framedIP net.IP, dns *net.Resolver) net.Dialer {
	return net.Dialer{
		LocalAddr: GetTcpDialAddr(framedIP),
		Resolver:  dns,

		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
}

func GetTcpDialAddr(addr net.IP) net.Addr {
	if addr != nil && !addr.IsLoopback() {
		return &net.TCPAddr{IP: addr}
	}
	return nil
}
