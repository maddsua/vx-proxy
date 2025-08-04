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
	//	Must return the list of required ports in the format of 'port/network', e.g. 1080/tcp
	BindsPorts() []string
}

type Validator interface {
	Validate() error
}

// Represents a port->service_id map
type PortSet map[string]string

func (this PortSet) Register(porter Porter, service string) error {

	for _, port := range porter.BindsPorts() {

		if reservedBy, has := this[port]; has {
			return fmt.Errorf("port %s already reserved for service %s", port, reservedBy)
		}

		this[port] = service
	}

	return nil
}

type Config struct {
	Auth     AuthConfig     `yaml:"auth"`
	Services ServicesConfig `yaml:"services"`
	Dns      dns.Config     `yaml:"dns"`
}

type AuthConfig struct {
	Radius auth.RadiusConfig `yaml:"radius"`
}

func (this *AuthConfig) Validate(portSet PortSet) error {

	if err := this.Radius.Validate(); err != nil {
		return fmt.Errorf("radius: %s", err.Error())
	}

	if err := portSet.Register(this.Radius, "radius"); err != nil {
		return err
	}

	return nil
}

func (this *Config) Validate() error {

	portSet := PortSet{}

	if err := this.Auth.Validate(portSet); err != nil {
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

	structVal := reflect.ValueOf(*this)
	structType := structVal.Type()

	for idx := 0; idx < structVal.NumField(); idx++ {

		val := structVal.Field(idx).Interface()
		field := strings.ToLower(structType.Field(idx).Name)

		if val, ok := val.(Porter); ok || val != nil {
			if err := portSet.Register(val, field); err != nil {
				return fmt.Errorf("%s: %v", field, err)
			}
		}

		if val, ok := val.(Validator); ok {
			if err := val.Validate(); err != nil {
				return fmt.Errorf("%s: %v", field, err)
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
