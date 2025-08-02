package utils

import (
	"errors"
	"net"
	"strconv"
	"strings"
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
