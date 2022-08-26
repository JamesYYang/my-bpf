package modules

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math"
	"my-bpf/assets"
	"my-bpf/config"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

type Woker struct {
	name              string
	config            config.WorkerConfiguration
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventMap          *ebpf.Map
	msgHandler        IMsgHandler
}

func (w *Woker) setupManager() {
	w.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				UID:              w.config.UID,
				Section:          w.config.Section,
				EbpfFuncName:     w.config.EbpfFuncName,
				AttachToFuncName: w.config.AttachToFuncName,
			},
		},
		Maps: []*manager.Map{
			{
				Name: w.config.MapName,
			},
		},
	}

	w.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
}

func (w *Woker) setupEventMap() error {
	em, found, err := w.bpfManager.GetMap(w.config.MapName)
	if err != nil {
		return err
	}
	if !found {
		return errors.New(fmt.Sprintf("cant found map:%s", w.config.MapName))
	}
	w.eventMap = em
	return nil
}

func (w *Woker) Run() error {
	log.Printf("[%s] begin start core", w.name)
	// fetch ebpf assets
	buf, err := assets.Asset(w.config.Asset)
	if err != nil {
		return errors.New(fmt.Sprintf("couldn't find asset %s", err))
	}
	// setup the managers
	w.setupManager()
	// initialize the bootstrap manager
	if err := w.bpfManager.InitWithOptions(bytes.NewReader(buf), w.bpfManagerOptions); err != nil {
		return errors.New(fmt.Sprintf("couldn't init manager, %s", err))
	}
	// start the bootstrap manager
	if err := w.bpfManager.Start(); err != nil {
		return errors.New("couldn't start bootstrap manager")
	}

	err = w.setupEventMap()
	if err != nil {
		return err
	}

	err = w.readEvents()
	if err != nil {
		return err
	}

	return nil
}

func (w *Woker) readEvents() error {
	var errChan = make(chan error, 8)
	event := w.eventMap
	log.Printf("[%s] begin read events", w.name)
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

		w.Decode(record.RawSample)
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
		w.Decode(record.RawSample)
	}
}

func (w *Woker) Decode(b []byte) {
	msg, err := w.msgHandler.Decode(b)
	if err != nil {
		log.Printf("decode error:%v", err)
	} else if msg != nil {
		log.Println(string(msg))
	}
}
