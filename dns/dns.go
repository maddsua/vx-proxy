package dns

import (
	"context"
	"fmt"
	"net"
	"time"
)

type Config struct {
	Server string `yaml:"server"`
}

func NewResolver(dnsaddr string) (*net.Resolver, error) {

	const defaultTimeout = 10 * time.Second

	//	set default DNS udp port
	var hostname string
	if host, _, err := net.SplitHostPort(dnsaddr); err != nil {
		hostname = dnsaddr
		dnsaddr = fmt.Sprintf("%s:%d", dnsaddr, 53)
	} else {
		hostname = host
	}

	//	check that hostname is correct
	if addr, _ := net.ResolveIPAddr("ip", hostname); addr == nil {
		return nil, fmt.Errorf("dns resolver: server unknown: %s", hostname)
	}

	//	make sure the server is actually up and running
	if err := ProbeDnsServer(dnsaddr); err != nil {
		return nil, fmt.Errorf("dns resolver: couldn't connect to the server at %s: %v", hostname, err)
	}

	rslv := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: defaultTimeout}
			return dialer.DialContext(ctx, network, dnsaddr)
		},
	}

	return rslv, nil
}
