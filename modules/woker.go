package modules

import (
	"errors"
	"fmt"
	"log"
	"my-bpf/config"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	manager "github.com/ehids/ebpfmanager"
)

type IWoker interface {
	Name() string
	Run() error
	Start() error
	Init()
	Decode(em *ebpf.Map, b []byte) (*BPFMessage, error)
}

type Woker struct {
	name              string
	core              IWoker
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventMap          *ebpf.Map
}

var workers = make(map[string]IWoker)

var mybpfConfig *config.Configuration

func initConfig() {
	log.Println("Read Config...")
	bpfConfig, err := config.NewConfig()
	if err != nil {
		panic(err)
	}
	mybpfConfig = bpfConfig
}

func Register(w IWoker) {
	if mybpfConfig == nil {
		initConfig()
	}
	name := w.Name()

	wConfig, ok := mybpfConfig.WokerConfig[name]
	if !ok || !wConfig.Enable {
		return
	}

	if _, ok := workers[name]; !ok {
		log.Printf("Register worker: %s", name)
		workers[name] = w
	}
}

// GetModules 获取modules列表
func GetWorkers() map[string]IWoker {
	return workers
}

func (w *Woker) SetChild(core IWoker) {
	w.core = core
}

func (w *Woker) Init() {
	panic("Woker.Init() not implemented yet")
}

func (w *Woker) Run() error {
	//  start
	log.Printf("[%s]begin start core", w.name)
	err := w.core.Start()
	if err != nil {
		return err
	}
	log.Printf("[%s]begin start event", w.name)
	err = w.readEvents()
	if err != nil {
		return err
	}
	return nil
}

func (w *Woker) Write(msg *BPFMessage) {
	if msg != nil {
		HandlerMessage(msg)
	}
}

func (w *Woker) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	panic("Woker.Decode() not implemented yet")
}

func (w *Woker) readEvents() error {
	var errChan = make(chan error, 8)
	event := w.eventMap
	log.Printf("[%s]begin read events", w.name)
	log.Println(event.String())
	switch {
	case event.Type() == ebpf.RingBuf:
		go w.ringbufEventReader(errChan, event)
	case event.Type() == ebpf.PerfEventArray:
		go w.perfEventReader(errChan, event)
	}

	for {
		select {
		case err := <-errChan:
			return err
		}
	}
}

func (w *Woker) perfEventReader(errChan chan error, em *ebpf.Map) {
	log.Printf("[%s]begin to read from perfbuf", w.name)
	rd, err := perf.NewReader(em, os.Getpagesize())
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}
	defer rd.Close()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			errChan <- fmt.Errorf("reading from perf event reader: %s", err)
			return
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		result, err := w.core.Decode(em, record.RawSample)
		if err != nil {
			log.Printf("this.child.decode error:%v", err)
			continue
		}

		// 上报数据
		w.Write(result)
	}
}

func (w *Woker) ringbufEventReader(errChan chan error, em *ebpf.Map) {
	log.Printf("[%s]begin to read from ringbuf", w.name)
	rd, err := ringbuf.NewReader(em)
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(), err)
		return
	}
	defer rd.Close()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			errChan <- fmt.Errorf("reading from ringbuf reader: %s", err)
			return
		}

		result, err := w.core.Decode(em, record.RawSample)
		if err != nil {
			log.Printf("this.child.decode error:%v", err)
			continue
		}

		// 上报数据
		w.Write(result)
	}
}
