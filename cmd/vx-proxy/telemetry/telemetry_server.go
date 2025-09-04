package telemetry

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maddsua/vx-proxy/utils"
)

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
}

func (this *Config) Validate() error {

	if this.ListenAddr == "" {
		return fmt.Errorf("listen_addr is missing")
	}

	if !utils.NetAddrFormatValid(this.ListenAddr) {
		return fmt.Errorf("listen_addr format invalid")
	}

	return nil
}

func (this Config) BindsPorts() []string {

	if _, port, err := net.SplitHostPort(this.ListenAddr); err == nil {
		return []string{fmt.Sprintf("%s/tcp", port)}
	}

	return nil
}

type Telemetry struct {
	Config

	AuthStatus ErrorRater

	srv     *http.Server
	runID   uuid.UUID
	runDate time.Time
}

type ErrorRater interface {
	Type() string
	ErrorRate() float64
}

func (this *Telemetry) ListenAndServe() error {

	this.runID = uuid.New()
	this.runDate = time.Now()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /public/status", func(wrt http.ResponseWriter, req *http.Request) {

		wrt.Header().Set("Content-Type", "application/json")

		json.NewEncoder(wrt).Encode(map[string]any{
			//	unique id of this specific service run
			"run_id": this.runID.String(),
			//	service uptime in seconds
			"uptime_s": int64(time.Since(this.runDate).Seconds()),
			//	auth controller metrics
			"auth": map[string]any{
				//	controller type
				"type": this.AuthStatus.Type(),
				//	controller error rate
				"error_rate": this.AuthStatus.ErrorRate(),
			},
		})
	})

	if host, _, _ := net.SplitHostPort(this.ListenAddr); strings.ToLower(host) == "localhost" {
		slog.Warn("TELEMETRY: 'localhost' is set as a listen address. This makes the service unreachable from the outside. Please consider using a specific address or an <unspecified>")
	}

	this.srv = &http.Server{
		Addr:    this.ListenAddr,
		Handler: mux,
	}

	return this.srv.ListenAndServe()
}

func (this *Telemetry) At() string {

	if this.Config.ListenAddr == "" {
		return ""
	}

	addr := this.Config.ListenAddr
	if host, port, err := net.SplitHostPort(addr); err != nil || host == "" {
		addr = net.JoinHostPort("localhost", port)
	}

	return fmt.Sprintf("http://%s/public/status", addr)
}

func (this *Telemetry) Close() error {

	if this.srv != nil {
		return this.srv.Close()
	}

	return nil
}
