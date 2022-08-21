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

type Sys_Openat_Woker struct {
	Woker
}

type Openat_Event struct {
	Pid      uint32
	Tgid     uint32
	Ppid     uint32
	Comm     [50]byte
	Filename [256]byte
	UtsName  [64]byte
}

func (w *Sys_Openat_Woker) Name() string {
	return w.name
}

func (w *Sys_Openat_Woker) Init() {
	w.Woker.SetChild(w)
}

func (w *Sys_Openat_Woker) setupManager() {
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
				Name: "sys_enter_openat_events",
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

func (w *Sys_Openat_Woker) setupEventMap() error {
	//eventMap 与解码函数映射
	em, found, err := w.bpfManager.GetMap("sys_enter_openat_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:sys_enter_openat_events")
	}
	w.eventMap = em
	return nil
}

func (w *Sys_Openat_Woker) Start() error {

	// fetch ebpf assets
	buf, err := assets.Asset("ebpf/bin/sys_openat.o")
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

func (w *Sys_Openat_Woker) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Openat_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return "", err
	}
	return fmt.Sprintf("comm: %s\t filename: %s\t UtsName: %s\t",
		unix.ByteSliceToString(event.Comm[:]), unix.ByteSliceToString(event.Filename[:]),
		unix.ByteSliceToString(event.UtsName[:])), nil
}

func init() {
	w := &Sys_Openat_Woker{}
	w.name = "EBPFSysOpenat"
	Register(w)
}