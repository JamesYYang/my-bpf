package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type (
	WorkerConfiguration struct {
		Name   string `yaml:"Name"`
		Enable bool   `yaml:"Enable"`
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
