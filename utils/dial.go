package utils

import (
	"net"
	"time"
)

func NewTcpDialer(framedIP net.IP, dns *net.Resolver) net.Dialer {
	return net.Dialer{
		LocalAddr: DialAddrTcp(framedIP),
		Resolver:  dns,

		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
}
