package modules

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math"
	"my-bpf/assets"
	"my-bpf/config"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

type Woker struct {
	name              string
	extBTF            string
	config            config.WorkerConfiguration
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventMap          *ebpf.Map
	msgHandler        IMsgHandler
}

func (w *Woker) setupTraceManager() {
	w.bpfManager = &manager.Manager{}
	for _, p := range w.config.Probes {
		probe := &manager.Probe{
			UID:              p.UID,
			Section:          p.Section,
			EbpfFuncName:     p.EbpfFuncName,
			AttachToFuncName: p.AttachToFuncName,
		}
		w.bpfManager.Probes = append(w.bpfManager.Probes, probe)
	}
}

func (w *Woker) setupXDPManager() {
	w.bpfManager = &manager.Manager{}
	for _, p := range w.config.Probes {
		probe := &manager.Probe{
			UID:          p.UID,
			Section:      p.Section,
			EbpfFuncName: p.EbpfFuncName,
			Ifname:       p.Ifname,
		}
		w.bpfManager.Probes = append(w.bpfManager.Probes, probe)
	}
}

func (w *Woker) setupTCManager() {
	w.bpfManager = &manager.Manager{}
	for _, p := range w.config.Probes {
		if p.Ifname == "All" {
			inets, err := net.Interfaces()
			if err != nil {
				panic(fmt.Sprintf("list interface failed, error: %v", err))
			}

			for _, i := range inets {
				if i.Flags&net.FlagLoopback == net.FlagLoopback {
					continue
				}
				probe := &manager.Probe{
					//show filter
					//tc filter show dev eth0 ingress(egress)
					// customize deleteed TC filter
					// tc filter del dev eth0 ingress(egress)
					UID:              p.UID + "_" + i.Name,
					Section:          p.Section,
					EbpfFuncName:     p.EbpfFuncName,
					Ifname:           i.Name,
					NetworkDirection: manager.Ingress,
				}
				if p.NetworkDirection == "Egress" {
					probe.NetworkDirection = manager.Egress
				}
				w.bpfManager.Probes = append(w.bpfManager.Probes, probe)
				log.Printf("add tc hook to net interface: %s", i.Name)
			}
		} else {
			probe := &manager.Probe{
				//show filter
				//tc filter show dev eth0 ingress(egress)
				// customize deleteed TC filter
				// tc filter del dev eth0 ingress(egress)
				UID:              p.UID,
				Section:          p.Section,
				EbpfFuncName:     p.EbpfFuncName,
				Ifname:           p.Ifname,
				NetworkDirection: manager.Ingress,
			}
			if p.NetworkDirection == "Egress" {
				probe.NetworkDirection = manager.Egress
			}
			w.bpfManager.Probes = append(w.bpfManager.Probes, probe)
			log.Printf("add tc hook to net interface: %s", p.Ifname)
		}
	}

}

func (w *Woker) setupManager() {
	if w.config.EbpfType == EBPF_TC {
		w.setupTCManager()
	} else if w.config.EbpfType == EBPF_XDP {
		w.setupXDPManager()
	} else {
		w.setupTraceManager()
	}

	w.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize:     2097152,
				KernelTypes: w.getBTFSpec(),
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
}

func (w *Woker) getBTFSpec() *btf.Spec {
	if w.extBTF == "" {
		return nil
	} else {
		spec, err := btf.LoadSpec(w.extBTF)
		if err != nil {
			log.Printf("load external BTF from [%s], failed, %v", w.extBTF, err)
			return nil
		} else {
			log.Printf("load external BTF from, %s", w.extBTF)
			return spec
		}
	}
}

func (w *Woker) setupEventMap() error {
	if w.config.MapName == "" {
		return nil
	}
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

func (w *Woker) setupKernelMap() error {
	if w.config.MapToKernel == "" {
		return nil
	}
	em, found, err := w.bpfManager.GetMap(w.config.MapToKernel)
	if err != nil {
		return err
	}
	if !found {
		return errors.New(fmt.Sprintf("cant found map:%s", w.config.MapToKernel))
	}
	err = w.msgHandler.SetupKernelMap(em)
	if err != nil {
		return err
	}
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

	err = w.setupKernelMap()
	if err != nil {
		return err
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
	if w.eventMap == nil {
		return nil
	}
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
	rd, err := perf.NewReader(em, w.config.PerfMapSize*os.Getpagesize())
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

func (w *Woker) Stop() {
	log.Printf("stopping worker: %s", w.name)
	err := w.bpfManager.Stop(manager.CleanAll)
	if err != nil {
		log.Printf("stop worker: %s failed, error: %v", w.name, err)
	}
}
