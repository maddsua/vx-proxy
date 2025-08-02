package utils

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

func GetLocalDialAddrTCP(addr net.Addr) *net.TCPAddr {

	if addr, ok := addr.(*net.TCPAddr); ok {
		if !addr.IP.IsLoopback() {
			return &net.TCPAddr{IP: addr.IP}
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

type Range struct {
	Begin int
	End   int
}

func ParseRange(token string) (*Range, error) {

	if token == "" {
		return nil, errors.New("empty token")
	}

	before, after, has := strings.Cut(token, "-")
	if !has {

		val, err := strconv.Atoi(token)
		if err != nil {
			return nil, err
		}

		return &Range{Begin: val, End: val}, nil
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
		return nil, errors.New("invalid range")
	}

	return &Range{Begin: begin, End: end}, nil
}
