package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Auth     AuthConfig     `yaml:"auth"`
	Services ServicesConfig `yaml:"services"`
	Dns      DnsConfig      `yaml:"dns"`
}

func (this *Config) Validate() error {

	if err := this.Auth.Validate(); err != nil {
		return fmt.Errorf("auth: %s", err.Error())
	}

	return nil
}

type AuthConfig struct {
	Radius RadiusConfig `yaml:"radius"`
}

func (this *AuthConfig) Validate() error {

	if err := this.Radius.Validate(); err != nil {
		return fmt.Errorf("radius: %s", err.Error())
	}

	return nil
}

type RadiusConfig struct {
	RemoteAddr string `yaml:"remote_addr"`
	AuthAddr   string `yaml:"auth_addr"`
	AcctAddr   string `yaml:"acct_addr"`
	LocalAddr  string `yaml:"local_addr"`
	Secret     string `yaml:"secret"`
}

func (this *RadiusConfig) Validate() error {

	LoadEnvValue(&this.RemoteAddr)
	LoadEnvValue(&this.LocalAddr)
	LoadEnvValue(&this.AuthAddr)
	LoadEnvValue(&this.AcctAddr)
	LoadEnvValue(&this.Secret)

	return nil
}

type ServicesConfig struct {
	Http  *HttpServiceConfig  `yaml:"http"`
	Socks *SocksServiceConfig `yaml:"socks"`
}

type HttpServiceConfig struct {
	PortRange string `yaml:"port_range"`
}

type SocksServiceConfig struct {
	PortRange string `yaml:"port_range"`
}

type DnsConfig struct {
	Server string `yaml:"server"`
}

func LoadConfigFile(path string) (*Config, error) {

	file, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %s", err.Error())
	}

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get config file info: %s", err.Error())
	}

	if !info.Mode().IsRegular() {
		return nil, errors.New("failed to read config file: config file must be a regular file")
	}

	var cfg Config

	if strings.HasSuffix(path, ".yml") {
		if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
			return nil, fmt.Errorf("failed to decode config file: %s", err.Error())
		}
	} else if strings.HasSuffix(path, ".json") {
		if err := json.NewDecoder(file).Decode(&cfg); err != nil {
			return nil, fmt.Errorf("failed to decode config file: %s", err.Error())
		}
	} else {
		return nil, errors.New("unsupported config file format")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %s", err.Error())
	}

	return &cfg, nil
}
