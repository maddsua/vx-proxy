package telemetry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
}

type Telemetry struct {
	Config

	AuthController ErrorRater

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
				"type": this.AuthController.Type(),
				//	controller error rate
				"error_rate": this.AuthController.ErrorRate(),
			},
		})
	})

	addr, err := this.getAddr()
	if err != nil {
		return err
	}

	this.srv = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return this.srv.ListenAndServe()
}

func (this *Telemetry) getAddr() (string, error) {

	if this.Config.ListenAddr != "" {
		return this.Config.ListenAddr, nil
	}

	return "", fmt.Errorf("listen addr is missing")
}

func (this *Telemetry) At() string {

	addr, err := this.getAddr()
	if err == nil {
		return fmt.Sprintf("http://%s/public/status", addr)
	}

	return ""
}

func (this *Telemetry) Close() error {

	if this.srv != nil {
		return this.srv.Close()
	}

	return nil
}
