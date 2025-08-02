package status

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

type Service struct {
	Config

	srv     *http.Server
	runID   uuid.UUID
	runDate time.Time
}

func (this *Service) ListenAndServe() error {

	this.runID = uuid.New()
	this.runDate = time.Now()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /status", func(wrt http.ResponseWriter, req *http.Request) {

		wrt.Header().Set("Content-Type", "application/json")

		json.NewEncoder(wrt).Encode(map[string]any{
			"run_id":   this.runID.String(),
			"uptime_s": int64(time.Since(this.runDate).Seconds()),
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

func (this *Service) getAddr() (string, error) {

	if this.Config.ListenAddr != "" {
		return this.Config.ListenAddr, nil
	}

	return "", fmt.Errorf("listen addr is missing")
}

func (this *Service) At() string {

	addr, err := this.getAddr()
	if err == nil {
		return fmt.Sprintf("http://%s/status", addr)
	}

	return ""
}

func (this *Service) Close() error {

	if this.srv != nil {
		return this.srv.Close()
	}

	return nil
}
