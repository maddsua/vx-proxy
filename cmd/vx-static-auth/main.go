package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	radius "github.com/maddsua/layeh-radius"
	"github.com/maddsua/vx-proxy/utils"
)

type CliFlags struct {
	CfgFile        *string
	AuthListenAddr *string
	AcctListenAddr *string
}

func main() {

	slog.Info("STARTING: vx-proxy static auth server")

	cli := CliFlags{
		CfgFile:        flag.String("cfg", "", "Provides config file location"),
		AuthListenAddr: flag.String("auth_addr", ":1812", "Set listen address for the auth service"),
		AcctListenAddr: flag.String("acct_addr", ":1813", "Set listen address for the accounting service"),
	}
	flag.Parse()

	if *cli.CfgFile == "" {

		loc, has := utils.FindLocation([]string{
			"./vx.dac.cfg.yml",
			"./vx-dac.yml",
			"/etc/vx-proxy/vx.dac.cfg.yml",
			"/etc/vx-proxy/vx-dac.yml",
		})

		if !has {
			slog.Error("No config file found")
			os.Exit(1)
		}

		cli.CfgFile = &loc
	}

	slog.Info("Loading config file",
		slog.String("from", *cli.CfgFile))

	cfg, err := LoadConfigFile(*cli.CfgFile)
	if err != nil {
		slog.Error("Failed to load config",
			slog.String("err", err.Error()))
		os.Exit(1)
	}

	var serverAddrOpt = func(flagVal string, cfgVal string) string {
		if cfgVal != "" {
			return cfgVal
		}
		return flagVal
	}

	authServer := radius.PacketServer{
		Handler:      authenticator{Users: cfg.Users},
		SecretSource: radius.StaticSecretSource([]byte(cfg.Radius.Secret)),
		Addr:         serverAddrOpt(*cli.AuthListenAddr, cfg.Radius.AuthListendAddr),
	}

	acctServer := radius.PacketServer{
		Handler:      radius.HandlerFunc(acctHandler),
		SecretSource: radius.StaticSecretSource([]byte(cfg.Radius.Secret)),
		Addr:         serverAddrOpt(*cli.AcctListenAddr, cfg.Radius.AcctListendAddr),
	}

	errCh := make(chan error, 1)
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())

	var shutdownAll = func() {

		cancel()

		authServer.Shutdown(ctx)
		authServer.Shutdown(ctx)
	}

	var startServer = func(service string, server *radius.PacketServer) {

		slog.Info("Starting",
			slog.String("svc", service),
			slog.String("addr", server.Addr))

		if err := server.ListenAndServe(); err != nil && ctx.Err() == nil {
			slog.Error("ListenAndServe",
				slog.String("svc", service),
				slog.String("err", err.Error()))
			errCh <- err
		}
	}

	go startServer("auth", &authServer)
	go startServer("acct", &acctServer)

	select {

	case <-errCh:
		slog.Error("Service terminated")
		shutdownAll()
		os.Exit(1)

	case <-exitCh:
		slog.Warn("Service vx-proxy static auth server is exiting...")
		shutdownAll()
		break
	}
}
