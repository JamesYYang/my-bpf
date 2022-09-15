package k8s

import (
	"time"
)

type MockCtroller struct {
	w *Watcher
}

func (mc *MockCtroller) StartMock() {
	go mc.doMock()
}

func (mc *MockCtroller) doMock() {
	// log.Printf("Worker [%s] start", w.Rules.HealthRuleId)
	time.Sleep(time.Duration(5 * time.Second))
	ticker := time.NewTicker(5 * time.Second)

	for mc.do() {
		<-ticker.C
	}
}

func (mc *MockCtroller) do() bool {
	addr := NetAddress{
		Host: "www.baidu.com",
		IP:   "10.16.75.24",
		Type: "Service",
	}

	mc.w.ServiceAdd <- addr
	return true
}
