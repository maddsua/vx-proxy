package utils

import (
	"net"
	"strings"
)

func GetReverseDialAddrTcp(conn net.Conn) *net.TCPAddr {

	if conn, ok := conn.(*net.TCPConn); ok {
		if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			if !addr.IP.IsLoopback() {
				return &net.TCPAddr{IP: addr.IP}
			}
		}
	}

	return nil
}

func GetAddrPort(addr net.Addr) (net.IP, int, bool) {

	if addr, ok := addr.(*net.TCPAddr); ok {
		return addr.IP, addr.Port, true
	}

	if addr, ok := addr.(*net.UDPAddr); ok {
		return addr.IP, addr.Port, true
	}

	return nil, 0, false
}

func IsPrivateNetwork(host string) bool {

	if val, _, err := net.SplitHostPort(host); err == nil {
		host = val
	}

	//	idk why I am always putting there everywhere lol
	host = strings.TrimSpace(host)
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() {
			return true
		}
	}

	return false
}

// Strips localhost prefix so that a listener that this is getting passed to would bind to all available addresses,
// and not just whatever go decides is good enough
func StripLocalhost(addr string) string {

	var isLocalhost = func(host string) bool {
		return strings.ToLower(host) == "localhost"
	}

	if host, port, err := net.SplitHostPort(addr); err == nil && isLocalhost(host) {
		return ":" + port
	}

	return addr
}

func NetAddrFormatValid(addr string) bool {
	_, _, err := net.SplitHostPort(addr)
	return err == nil
}
