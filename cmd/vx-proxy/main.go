package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/cmd/vx-proxy/telemetry"
	"github.com/maddsua/vx-proxy/dns"
	"github.com/maddsua/vx-proxy/socks"
	"github.com/maddsua/vx-proxy/utils"

	httproxy "github.com/maddsua/vx-proxy/http"
)

type CliFlags struct {
	Debug   *bool
	CfgFile *string
	LogFmt  *string
}

func main() {

	godotenv.Load()

	cli := CliFlags{
		Debug:   flag.Bool("debug", false, "Show debug logging"),
		CfgFile: flag.String("config", "", "Set config value path"),
		LogFmt:  flag.String("logfmt", "", "Log format: json|null"),
	}
	flag.Parse()

	if strings.ToLower(os.Getenv("LOG_FMT")) == "json" || strings.ToLower(*cli.LogFmt) == "json" {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	}

	slog.Info("Service vx-proxy starting...")

	if *cli.CfgFile == "" {

		loc, has := utils.FindLocation([]string{
			"./vx-proxy.yml",
			"/etc/vx-proxy/vx-proxy.yml",
		})

		if !has {
			slog.Error("No config file found")
			os.Exit(1)
		}

		cli.CfgFile = &loc
	}

	slog.Info("Loading config file",
		slog.String("from", *cli.CfgFile))

	cfg, err := loadConfigFile(*cli.CfgFile)
	if err != nil {
		slog.Error("Failed to load config file",
			slog.String("err", err.Error()))
		os.Exit(1)
	}

	if *cli.Debug || cfg.Debug || strings.ToLower(os.Getenv("LOG_LEVEL")) == "debug" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Debug("Enabled")
	}

	var customDNS *net.Resolver

	var setCustomDns = func(addr string) {

		rslv, err := dns.NewResolver(addr)
		if err != nil {
			slog.Error("Failed to enable custom DNS resolver",
				slog.String("err", err.Error()))
			os.Exit(1)
		}

		customDNS = rslv

		slog.Info("Using a custom DNS resolver",
			slog.String("addr", addr))
	}

	if val := os.Getenv("VX_USE_DNS"); val != "" {
		setCustomDns(val)
	} else if cfg.Dns.Server != "" {
		setCustomDns(cfg.Dns.Server)
	}

	authc, err := auth.NewRadiusController(cfg.Auth.Radius)
	if err != nil {
		slog.Error("Failed to start radius controller",
			slog.String("err", err.Error()))
		os.Exit(1)
	}

	slog.Info("RADIUS auth enabled",
		slog.String("auth_addr", cfg.Auth.Radius.AuthAddr),
		slog.String("acct_addr", cfg.Auth.Radius.AcctAddr),
		slog.String("listen_dac", cfg.Auth.Radius.ListenDAC))

	errCh := make(chan error, 1)
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, syscall.SIGINT, syscall.SIGTERM)

	if cfg.Services.Http != nil {

		svc := httproxy.HttpServer{
			Config: *cfg.Services.Http,
			Auth:   authc,
			Dns:    customDNS,
		}

		go func() {
			if err := svc.ListenAndServe(); err != nil {
				errCh <- errors.New("http service error: " + err.Error())
			}
		}()

		defer svc.Close()

		slog.Info("Starting http service",
			slog.String("range", cfg.Services.Http.PortRange))
	}

	if cfg.Services.Socks != nil {

		svc := socks.SocksServer{
			Config: *cfg.Services.Socks,
			Auth:   authc,
			Dns:    customDNS,
		}

		go func() {
			if err := svc.ListenAndServe(); err != nil {
				errCh <- errors.New("socks service error: " + err.Error())
			}
		}()

		defer svc.Close()

		slog.Info("Starting socks service",
			slog.String("range", cfg.Services.Socks.PortRange))
	}

	if cfg.Services.Telemetry != nil {

		svc := telemetry.Telemetry{
			Config:     *cfg.Services.Telemetry,
			AuthStatus: authc,
		}

		go func() {
			if err := svc.ListenAndServe(); err != nil {
				errCh <- errors.New("telementry service error: " + err.Error())
			}
		}()

		slog.Info("Starting telementry service",
			slog.String("at", svc.At()))

		defer svc.Close()
	}

	select {
	case err := <-errCh:
		slog.Error("Service crashed",
			slog.String("err", err.Error()))
		os.Exit(1)
	case <-exitCh:

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		authc.Shutdown(ctx)

		slog.Warn("Service vx-proxy is exiting...")
		break
	}
}
