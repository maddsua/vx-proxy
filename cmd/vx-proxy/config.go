package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/cmd/vx-proxy/status"
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
	Http   *http.Config   `yaml:"http"`
	Socks  *socks.Config  `yaml:"socks"`
	Status *status.Config `yaml:"status"`
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

func parseRange(token string) ([2]int, error) {

	if token == "" {
		return [2]int{}, errors.New("empty token")
	}

	before, after, has := strings.Cut(token, "-")
	if !has {

		val, err := strconv.Atoi(token)
		if err != nil {
			return [2]int{}, err
		}

		return [2]int{val, val}, nil
	}

	begin, err := strconv.Atoi(strings.TrimSpace(before))
	if err != nil {
		return [2]int{}, err
	}

	end, err := strconv.Atoi(strings.TrimSpace(after))
	if err != nil {
		return [2]int{}, err
	}

	if end <= begin {
		return [2]int{}, errors.New("invalid range")
	}

	return [2]int{begin, end}, nil
}
