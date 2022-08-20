package modules

import (
	"os"
	"strconv"
)

type EnvInfo struct {
	StartProbe string
}

var MyBpfEnv = EnvInfo{
	StartProbe: os.Getenv("BPF_STARTPROBE"),
}

func parseEnvToInt(envName string, defaultNum int) int {
	connEnv := os.Getenv(envName)
	if connEnv != "" {
		result, err := strconv.Atoi(connEnv)
		if err == nil {
			return result
		}
	}
	return defaultNum
}
