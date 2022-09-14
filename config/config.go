package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type (
	WorkerConfiguration struct {
		EbpfType    string  `yaml:"EbpfType"`
		PerfMapSize int     `yaml:"PerfMapSize"`
		Asset       string  `yaml:"Asset"`
		Enable      bool    `yaml:"Enable"`
		Probes      []Probe `yaml:"Probes"`
		MapName     string  `yaml:"MapName"`
		MapToKernel string  `yaml:"MapToKernel"`
		MsgHandler  string  `yaml:"MsgHandler"`
	}

	Probe struct {
		UID              string `yaml:"UID"`
		Section          string `yaml:"Section"`
		EbpfFuncName     string `yaml:"EbpfFuncName"`
		AttachToFuncName string `yaml:"AttachToFuncName"`
		Ifname           string `yaml:"Ifname"`
		NetworkDirection string `yaml:"NetworkDirection"`
	}

	Configuration struct {
		ExtBTF      string                         `yaml:"ExtBTF"`
		EnableK8S   bool                           `yaml:"EnableK8S"`
		IsInK8S     bool                           `yaml:"IsInK8S"`
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
