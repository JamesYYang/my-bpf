package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type (
	WorkerConfiguration struct {
		UID              string `yaml:"UID"`
		Section          string `yaml:"Section"`
		EbpfFuncName     string `yaml:"EbpfFuncName"`
		AttachToFuncName string `yaml:"AttachToFuncName"`
		MapName          string `yaml:"MapName"`
		PerfMapSize      int    `yaml:"PerfMapSize"`
		Asset            string `yaml:"Asset"`
		Enable           bool   `yaml:"Enable"`
	}

	Configuration struct {
		WokerConfig map[string]WorkerConfiguration `yaml:"WokerConfig"`
	}
)

func NewConfig() (*Configuration, error) {
	fname := "config/config.yaml"

	configuration := &Configuration{}
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(data, configuration); err != nil {
		return nil, err
	}

	return configuration, nil
}
