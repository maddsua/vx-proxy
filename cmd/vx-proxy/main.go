package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/joho/godotenv"
	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/utils"

	httproxy "github.com/maddsua/vx-proxy/http"
	socksproxy "github.com/maddsua/vx-proxy/socks"
)

//	todo: print remote addresses

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

	if *cli.Debug || strings.ToLower(os.Getenv("LOG_LEVEL")) == "debug" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Debug("Enabled")
	}

	if *cli.CfgFile == "" {

		loc, has := utils.FindLocation([]string{
			"./vx.cfg.yml",
			"./vx-proxy.yml",
			"/etc/vx-proxy/vx.cfg.yml",
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

	var customDNS *net.Resolver

	var setCustomDns = func(addr string) {

		rslv, err := utils.NewCustomResolver(addr)
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

	defer authc.Close()

	errCh := make(chan error, 1)
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, syscall.SIGINT, syscall.SIGTERM)

	if cfg.Services.Http != nil {

		ports, err := parseRange(cfg.Services.Http.PortRange)
		if err != nil {
			slog.Error("Invalid config: Invalid http swarm port range",
				slog.String("err", err.Error()))
			os.Exit(1)
		}

		slog.Info(fmt.Sprintf("Summoning http swarm at [%d...%d]/tcp", ports[0], ports[1]))

		swarm := &utils.SwarmServer{
			Ports: utils.UnwarpPortRange(ports),
			Handler: func(ctx context.Context, listener net.Listener) {

				portSrv := http.Server{
					Handler: &httproxy.Proxy{
						Auth: authc,
						Dns:  customDNS,
					},
					ConnContext: func(connCtx context.Context, conn net.Conn) context.Context {
						return httproxy.SetContextLocalAddr(connCtx, conn.LocalAddr())
					},
				}

				defer portSrv.Close()

				go func() {
					if err := portSrv.Serve(listener); err != nil && ctx.Err() == nil {
						errCh <- fmt.Errorf("http swarm serve task %s error: %s", listener.Addr().String(), err.Error())
					}
				}()

				<-ctx.Done()
			},
		}

		go func() {
			if err := swarm.Serve(); err != nil {
				errCh <- errors.New("http swarm error: " + err.Error())
			}
		}()

		defer swarm.Close()
	}

	if cfg.Services.Socks != nil {

		ports, err := parseRange(cfg.Services.Socks.PortRange)
		if err != nil {
			slog.Error("Invalid config: Invalid socks swarm port range",
				slog.String("err", err.Error()))
			os.Exit(1)
		}

		slog.Info(fmt.Sprintf("Summoning socks swarm at [%d...%d]/tcp", ports[0], ports[1]))

		swarm := &utils.SwarmServer{
			Ports: utils.UnwarpPortRange(ports),
			Handler: func(ctx context.Context, listener net.Listener) {

				portSrv := socksproxy.SocksServer{
					Handler: &socksproxy.Proxy{
						Auth: authc,
						Dns:  customDNS,
					},
				}

				defer portSrv.Close()

				go func() {
					if err := portSrv.Serve(listener); err != nil && ctx.Err() == nil {
						errCh <- fmt.Errorf("socks swarm serve task %s error: %s", listener.Addr().String(), err.Error())
					}
				}()

				<-ctx.Done()
			},
		}

		go func() {
			if err := swarm.Serve(); err != nil {
				errCh <- errors.New("socks swarm error: " + err.Error())
			}
		}()

		defer swarm.Close()
	}

	select {
	case err := <-errCh:
		slog.Error("Service crashed",
			slog.String("err", err.Error()))
		os.Exit(1)
	case <-exitCh:
		slog.Warn("Service vx-proxy is exiting...")
		break
	}
}
