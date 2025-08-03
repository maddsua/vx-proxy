package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/maddsua/vx-proxy/auth"
	"github.com/maddsua/vx-proxy/cmd/vx-proxy/telemetry"
	"github.com/maddsua/vx-proxy/dns"
	"github.com/maddsua/vx-proxy/http"
	"github.com/maddsua/vx-proxy/socks"
	"gopkg.in/yaml.v3"
)

type Porter interface {
	ServiceID() string
	//	Must return the list of required ports in the format of 'port/network', e.g. 1080/tcp
	BindsPorts() []string
}

// Represents a port->service_id map
type PortSet map[string]string

func (this PortSet) Register(service Porter) error {

	for _, port := range service.BindsPorts() {

		if reservedBy, has := this[port]; has {
			return fmt.Errorf("port %s already reserved by service '%s'", port, reservedBy)
		}

		this[port] = service.ServiceID()
	}

	return nil
}

type Config struct {
	Auth     auth.Config    `yaml:"auth"`
	Services ServicesConfig `yaml:"services"`
	Dns      dns.Config     `yaml:"dns"`
}

func (this *Config) Validate() error {

	portSet := PortSet{}

	if err := this.Auth.Validate(); err != nil {
		return fmt.Errorf("auth: %s", err.Error())
	}

	if err := this.Services.Validate(portSet); err != nil {
		return fmt.Errorf("services: %s", err.Error())
	}

	return nil
}

type ServicesConfig struct {
	Http      *http.Config      `yaml:"http"`
	Socks     *socks.Config     `yaml:"socks"`
	Telemetry *telemetry.Config `yaml:"telemetry"`
}

func (this *ServicesConfig) Validate(portSet PortSet) error {

	stuctVal := reflect.ValueOf(*this)

	for idx := 0; idx < stuctVal.NumField(); idx++ {
		if val, ok := stuctVal.Field(idx).Interface().(Porter); ok || val != nil {
			if err := portSet.Register(val); err != nil {
				return err
			}
		}
	}

	return nil
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
