package modules

import (
	"log"
	"my-bpf/config"
	"my-bpf/k8s"
)

type WokerDispatch struct {
	Wokers       []*Woker
	BPFConfig    *config.Configuration
	K8SWatcher   *k8s.Watcher
	eventHandler *EventHandler
}

func NewWorkerDispatch() (*WokerDispatch, error) {
	log.Println("Read Config...")
	bpfConfig, err := config.NewConfig()
	if err != nil {
		return nil, err
	}
	wd := &WokerDispatch{}
	wd.BPFConfig = bpfConfig
	wd.eventHandler = NewEventHandler(bpfConfig)
	return wd, nil
}

func (wd *WokerDispatch) InitWorkers() {
	for n, c := range wd.BPFConfig.WokerConfig {
		if c.Enable {
			w := &Woker{}
			w.name = n
			w.wd = wd
			w.config = c
			w.extBTF = wd.BPFConfig.ExtBTF
			w.msgHandler = msgHandlers[c.MsgHandler]
			wd.Wokers = append(wd.Wokers, w)
		}
	}
}

func (wd *WokerDispatch) Run() {
	for _, w := range wd.Wokers {
		log.Printf("start to run %s module", w.name)
		// 加载ebpf，挂载到hook点上，开始监听
		go func(w *Woker) {
			err := w.Run()
			if err != nil {
				log.Printf("%v\n", err)
			}
		}(w)
	}
}

func (wd *WokerDispatch) Stop() {
	for _, w := range wd.Wokers {
		w.Stop()
	}
}
