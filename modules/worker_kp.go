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

type KPWoker struct {
	Woker
}

type KPEvent struct {
	Pid  int32
	Comm [80]uint8
}

func (w *KPWoker) Name() string {
	return w.name
}

func (w *KPWoker) Init() {
	w.Woker.SetChild(w)
}

func (w *KPWoker) setupManager() {
	w.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				UID:              "MySysExecve",
				Section:          "kprobe/sys_execve",
				EbpfFuncName:     "kprobe_execve",
				AttachToFuncName: "__x64_sys_execve",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "events",
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

func (w *KPWoker) setupEventMap() error {
	//eventMap 与解码函数映射
	em, found, err := w.bpfManager.GetMap("events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	w.eventMap = em
	return nil
}

func (w *KPWoker) Start() error {

	// fetch ebpf assets
	buf, err := assets.Asset("ebpf/bin/kp.o")
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

func (w *KPWoker) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event KPEvent
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return "", err
	}
	return fmt.Sprintf("pid: %d\tcomm: %s\n", event.Pid, unix.ByteSliceToString(event.Comm[:])), nil
}

func init() {
	w := &KPWoker{}
	w.name = "EBPFKProbe"
	Register(w)
}
