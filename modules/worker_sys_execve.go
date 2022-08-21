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

type Sys_Execve_Woker struct {
	Woker
}

type Execve_Event struct {
	Pid      uint32
	Tgid     uint32
	Ppid     uint32
	Comm     [50]byte
	Filename [50]byte
	UtsName  [64]byte
}

func (w *Sys_Execve_Woker) Name() string {
	return w.name
}

func (w *Sys_Execve_Woker) Init() {
	w.Woker.SetChild(w)
}

func (w *Sys_Execve_Woker) setupManager() {
	w.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "tracepoint/syscalls/sys_enter_execve",
				EbpfFuncName:     "tracepoint_sys_enter_execve",
				AttachToFuncName: "sys_enter_execve",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "sys_enter_execve_events",
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

func (w *Sys_Execve_Woker) setupEventMap() error {
	//eventMap 与解码函数映射
	em, found, err := w.bpfManager.GetMap("sys_enter_execve_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:sys_enter_execve_events")
	}
	w.eventMap = em
	return nil
}

func (w *Sys_Execve_Woker) Start() error {

	// fetch ebpf assets
	buf, err := assets.Asset("ebpf/bin/sys_execve.o")
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
		return errors.New(fmt.Sprintf("couldn't start bootstrap manager, %s", err.Error()))
	}

	// 加载map信息，map对应events decode表。
	err = w.setupEventMap()
	if err != nil {
		return err
	}

	return nil
}

func (w *Sys_Execve_Woker) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Execve_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return "", err
	}
	return fmt.Sprintf("comm: %s\t filename: %s\t UtsName: %s\t",
		unix.ByteSliceToString(event.Comm[:]), unix.ByteSliceToString(event.Filename[:]),
		unix.ByteSliceToString(event.UtsName[:])), nil
}

func init() {
	w := &Sys_Execve_Woker{}
	w.name = "EBPFSysExecve"
	Register(w)
}
