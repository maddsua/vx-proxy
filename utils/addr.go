package utils

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func GetAddrPort(addr net.Addr) (net.IP, int, bool) {

	if addr, ok := addr.(*net.TCPAddr); ok {
		return addr.IP, addr.Port, true
	}

	if addr, ok := addr.(*net.UDPAddr); ok {
		return addr.IP, addr.Port, true
	}

	return nil, 0, false
}

type PortRange struct {
	First int
	Last  int
}

func ParsePortRange(token string) (*PortRange, error) {

	if token == "" {
		return nil, errors.New("empty token")
	}

	before, after, has := strings.Cut(token, "-")
	if !has {

		val, err := strconv.Atoi(token)
		if err != nil {
			return nil, err
		}

		return &PortRange{First: val, Last: val}, nil
	}

	begin, err := strconv.Atoi(strings.TrimSpace(before))
	if err != nil {
		return nil, err
	}

	end, err := strconv.Atoi(strings.TrimSpace(after))
	if err != nil {
		return nil, err
	}

	if end <= begin {
		return nil, errors.New("invalid port range")
	}

	return &PortRange{First: begin, Last: end}, nil
}

func DestHostAllowed(host string) error {

	if val, _, err := net.SplitHostPort(host); err == nil {
		host = val
	}

	//	idk why I am always putting there everywhere lol
	host = strings.TrimSpace(host)

	switch host {
	case "localhost", "127.0.0.1", "::1":
		return fmt.Errorf("localhost addresses not allowed")
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() {
			return fmt.Errorf("private addresses not allowed")
		}
	}

	return nil
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

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	_, err = strconv.Atoi(port)

	return err == nil
}

type AddrContainer interface {
	Contains(val net.IP) bool
}

// I am pretty much making this up;
// just pretend that it was written by an LLM
type AddrEqualer interface {
	Equal(val net.IP) bool
}

// Reports whether or not an address is assigned to the current host
func AddrAssigned(addr net.IP) (bool, error) {

	table, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}

	for _, val := range table {

		switch val := val.(type) {
		case AddrContainer:
			if val.Contains(addr) {
				return true, nil
			}
		case AddrEqualer:
			if val.Equal(addr) {
				return true, nil
			}
		default:
			return false, fmt.Errorf("unexpected interface type: %T", val)
		}
	}

	return false, nil
}
