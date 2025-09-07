package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadConfigFile(path string) (*FileConfig, error) {

	file, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("unable to open file at '%s'", path)
	}

	var cfg FileConfig
	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config file: %s", err.Error())
	}

	return &cfg, nil
}

type FileConfig struct {
	Radius RadiusConfig `yaml:"radius"`
	Users  []UserConfig `yaml:"users"`
}

type RadiusConfig struct {
	AuthListendAddr string `yaml:"auth_addr"`
	AcctListendAddr string `yaml:"acct_addr"`
	Secret          string `yaml:"secret"`
}

type UserConfig struct {
	Name       string `yaml:"name"`
	Pass       string `yaml:"pass"`
	RateRx     int    `yaml:"rate_rx"`
	RateTx     int    `yaml:"rate_tx"`
	MinRateRx  int    `yaml:"min_rate_rx"`
	MinRateTx  int    `yaml:"min_rate_tx"`
	MaxRateRx  int    `yaml:"max_rate_rx"`
	MaxRateTx  int    `yaml:"max_rate_tx"`
	ProxyAddr  string `yaml:"proxy_addr"`
	ProxyPort  int    `yaml:"proxy_port"`
	SessionTTL int    `yaml:"session_ttl"`
}
