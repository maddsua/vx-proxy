package socks

import (
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"
)

const (
	v5Ver          = byte(0x05)
	v5ByteReserved = byte(0x00)

	v5AddrTypeIPv4     = byte(0x01)
	v5AddrTypeHostname = byte(0x03)
	v5AddrTypeIPv6     = byte(0x04)

	v5AuthNone         = byte(0x00)
	v5AuthGSSAPI       = byte(0x01)
	v5AuthPassword     = byte(0x02)
	v5AuthUnacceptable = byte(0xff)

	v5CmdConnect   = byte(0x01)
	v5CmdBind      = byte(0x02)
	v5CmdAssociate = byte(0x03)

	v5RepOk                      = byte(0x00)
	v5RepErrGeneric              = byte(0x01)
	v5RepErrConnNotAllowed       = byte(0x02)
	v5RepErrNetUnreachable       = byte(0x03)
	v5RepErrHostUnreachable      = byte(0x04)
	v5RepErrConnRefused          = byte(0x05)
	v5RepErrTtlExpired           = byte(0x06)
	v5RepErrCmdNotSupported      = byte(0x07)
	v5RepErrAddrTypeNotSupported = byte(0x08)

	v5PasswordAuthVer     = byte(0x01)
	v5PasswordAuthRepOk   = byte(0x00)
	v5PasswordAuthRepFail = byte(0x01)
)

func v5ReadCredentials(reader io.Reader) (*auth.ProxyUser, error) {

	buff, err := utils.ReadBuffN(reader, 2)
	if err != nil {
		return nil, err
	}

	ver := buff[0]
	ulen := buff[1]

	if ver != 0x01 {
		return nil, errors.New("invalid auth version")
	} else if ulen == 0 {
		return nil, errors.New("empty username field")
	}

	unamePlus, err := utils.ReadBuffN(reader, int(ulen)+1)
	if err != nil {
		return nil, err
	}

	plen := unamePlus[int(ulen)]
	if plen == 0 {
		return nil, err
	}

	pass, err := utils.ReadBuffN(reader, int(plen))
	if err != nil {
		return nil, err
	}

	return &auth.ProxyUser{
		Username: string(unamePlus[:int(ulen)]),
		Password: string(pass),
	}, nil
}

func v5ReadAddr(reader io.Reader) (string, error) {

	addrType, err := utils.ReadByte(reader)
	if err != nil {
		return "", err
	}

	var addrLen uint8
	var addrIsIP bool

	switch addrType {

	case v5AddrTypeIPv4:
		addrLen = net.IPv4len
		addrIsIP = true

	case v5AddrTypeIPv6:
		addrLen = net.IPv6len
		addrIsIP = true

	case v5AddrTypeHostname:
		addrLen, err = utils.ReadByte(reader)
		if err != nil {
			return "", err
		}

	default:
		return "", errors.New("invalid socks v5 dst addr type")
	}

	addrBuff, err := utils.ReadBuffN(reader, int(addrLen))
	if err != nil {
		return "", err
	}

	portBuff, err := utils.ReadBuffN(reader, 2)
	if err != nil {
		return "", err
	}

	var hostname string
	if addrIsIP {
		hostname = net.IP(addrBuff).String()
	} else {
		hostname = string(addrBuff)
	}

	port := strconv.Itoa((int(portBuff[0]) << 8) | int(portBuff[1]))

	return net.JoinHostPort(hostname, port), nil
}

func v5PackAddr(addr string) []byte {

	if addr == "" {
		return nil
	}

	var buff []byte

	hostStr, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}

	hostAddr := net.ParseIP(hostStr)

	switch {
	case len(hostAddr) == net.IPv4len:
		buff = append(buff, v5AddrTypeIPv4)
		buff = append(buff, hostAddr...)
	case len(hostAddr) == net.IPv6len:
		buff = append(buff, v5AddrTypeIPv6)
		buff = append(buff, hostAddr...)
	default:
		buff = append(buff, v5AddrTypeHostname, byte(len(hostStr)&0xff))
		buff = append(buff, hostStr...)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}

	buff = append(buff, byte(port>>8), byte(port&0xff))
	if len(buff) >= 0xff {
		return nil
	}

	return buff
}
