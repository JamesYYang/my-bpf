package k8s

import (
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type MockService struct {
	EndpointList []NetAddress `yaml:"EndpointList"`
}

type MockCtroller struct {
	w *Watcher
}

func (mc *MockCtroller) StartMock() {
	go mc.doMock()
}

func (mc *MockCtroller) doMock() {
	fname := "config/mock.yaml"

	ms := &MockService{}
	data, err := os.ReadFile(fname)
	if err != nil {
		log.Printf("read mock file error: %v", err)
		return
	}
	if err = yaml.Unmarshal(data, ms); err != nil {
		log.Printf("read mock file error: %v", err)
		return
	}

	for _, e := range ms.EndpointList {
		log.Printf("endpoint add: [%s -- %s]\n", e.Host, e.IP)
		mc.w.IpCtrl.AddEndpoint([]NetAddress{e})
		time.Sleep(5 * time.Second)
	}
}
