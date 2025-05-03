package utils

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
)

func NewCustomResolver(dnsSrvAddr string) (*net.Resolver, error) {

	if _, _, err := net.SplitHostPort(dnsSrvAddr); err != nil {
		return nil, errors.New("custom DNS server address invalid: " + err.Error())
	}

	rslv := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {

			dialer := net.Dialer{}

			dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()

			_, port, _ := net.SplitHostPort(address)
			if port != "53" {
				slog.Debug("Custom DNS resolver: Unsupported dial passthrough",
					slog.String("net", network),
					slog.String("addr", address))
				return dialer.DialContext(dialCtx, network, address)
			}

			return dialer.DialContext(dialCtx, network, dnsSrvAddr)
		},
	}

	return rslv, ResolverTest(rslv)
}

func ResolverTest(rslv *net.Resolver) error {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	targets := []string{
		"google.com",
		"one.one.one.one",
		"a.root-servers.net",
		"k.root-servers.net",
		"m.root-servers.net",
	}

	var wg sync.WaitGroup
	done := make(chan bool, len(targets)+1)

	for _, target := range targets {

		wg.Add(1)

		go func() {

			defer func() {
				wg.Done()
			}()

			if addrs, err := rslv.LookupHost(ctx, target); len(addrs) > 0 {
				done <- true
			} else if err != nil {
				slog.Debug("DNS resolve test: Case failed",
					slog.String("case", target),
					slog.String("err", err.Error()))
			}
		}()
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	if dnsOk, ok := <-done; !dnsOk || !ok {
		return errors.New("unable to resolve none of the test domains")
	}

	return nil
}

func ResolveRemote(ctx context.Context, rslv *net.Resolver, addr string) (string, error) {

	if rslv == nil {
		return addr, nil
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "80"
	}

	addrs, err := rslv.LookupHost(ctx, host)
	if err != nil {
		return "", err
	} else if len(addrs) == 0 {
		return "", errors.New("unable to resolve host: " + host)
	}

	return net.JoinHostPort(addrs[0], port), nil
}
