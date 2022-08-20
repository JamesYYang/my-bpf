package modules

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"my-bpf/assets"

	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

type TPWoker struct {
	Woker
}

type TPEvent struct {
	Pid      int32
	Filename [256]byte
}

func (w *TPWoker) Name() string {
	return w.name
}

func (w *TPWoker) Init() {
	w.Woker.SetChild(w)
}

func (w *TPWoker) setupManager() {
	w.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "tracepoint/syscalls/sys_enter_openat",
				EbpfFuncName:     "tracepoint_openat",
				AttachToFuncName: "sys_enter_openat",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "tp_events",
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

func (w *TPWoker) setupEventMap() error {
	//eventMap 与解码函数映射
	em, found, err := w.bpfManager.GetMap("tp_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tp_events")
	}
	w.eventMap = em
	return nil
}

func (w *TPWoker) Start() error {

	// fetch ebpf assets
	buf, err := assets.Asset("ebpf/bin/tp.o")
	if err != nil {
		return errors.New("couldn't find asset")
	}
	// setup the managers
	w.setupManager()
	// initialize the bootstrap manager
	if err := w.bpfManager.InitWithOptions(bytes.NewReader(buf), w.bpfManagerOptions); err != nil {
		return errors.New("couldn't init manager")
	}
	// start the bootstrap manager
	if err := w.bpfManager.Start(); err != nil {
		return errors.New("couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = w.setupEventMap()
	if err != nil {
		return err
	}

	return nil
}

func (w *TPWoker) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event TPEvent
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return "", err
	}
	return fmt.Sprintf("pid: %d\tfilename: %s\n", event.Pid, unix.ByteSliceToString(event.Filename[:])), nil
}

func init() {
	w := &TPWoker{}
	w.name = "EBPFTProbe"
	Register(w)
}
