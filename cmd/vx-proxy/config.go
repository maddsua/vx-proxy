package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/cmd/vx-proxy/telemetry"
	"github.com/maddsua/vx-proxy/dns"
	"github.com/maddsua/vx-proxy/http"
	"github.com/maddsua/vx-proxy/socks"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Auth     auth.Config    `yaml:"auth"`
	Services ServicesConfig `yaml:"services"`
	Dns      dns.Config     `yaml:"dns"`
}

func (this *Config) Validate() error {

	if err := this.Auth.Validate(); err != nil {
		return fmt.Errorf("auth: %s", err.Error())
	}

	return nil
}

type ServicesConfig struct {
	Http      *http.Config      `yaml:"http"`
	Socks     *socks.Config     `yaml:"socks"`
	Telemetry *telemetry.Config `yaml:"telemetry"`
}

func loadConfigFile(path string) (*Config, error) {

	file, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("unable to open file at '%s'", path)
	}

	var cfg Config

	if strings.HasSuffix(path, ".yml") {
		if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
			return nil, fmt.Errorf("invalid config file: %s", err.Error())
		}
	} else if strings.HasSuffix(path, ".json") {
		if err := json.NewDecoder(file).Decode(&cfg); err != nil {
			return nil, fmt.Errorf("invalid config file: %s", err.Error())
		}
	} else {
		return nil, errors.New("unsupported config file format")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config options: %s", err.Error())
	}

	return &cfg, nil
}
