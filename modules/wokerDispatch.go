package modules

import (
	"log"
	"my-bpf/config"
)

type WokerDispatch struct {
	Wokers    []*Woker
	BPFConfig *config.Configuration
}

func NewWorkerDispatch() (*WokerDispatch, error) {
	log.Println("Read Config...")
	bpfConfig, err := config.NewConfig()
	if err != nil {
		return nil, err
	}
	wd := &WokerDispatch{}
	wd.BPFConfig = bpfConfig
	return wd, nil
}

func (wd *WokerDispatch) InitWorkers() {
	for n, c := range wd.BPFConfig.WokerConfig {
		if c.Enable {
			w := &Woker{}
			w.name = n
			w.config = c
			w.extBTF = wd.BPFConfig.ExtBTF
			w.msgHandler = msgHandlers[c.MapName]
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
