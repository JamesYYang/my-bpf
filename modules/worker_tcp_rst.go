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

type TCP_RST_Woker struct {
	Woker
}

type TCP_Exception_Event struct {
	Sip   uint32
	Dip   uint32
	Sport uint16
	Dport uint16
}

func (w *TCP_RST_Woker) Name() string {
	return w.name
}

func (w *TCP_RST_Woker) Init() {
	w.Woker.SetChild(w)
}

func (w *TCP_RST_Woker) setupManager() {
	w.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				UID:              "MySysTcpRST",
				Section:          "kprobe/tcp_v4_send_reset",
				EbpfFuncName:     "kp_tcp_v4_send_reset",
				AttachToFuncName: "tcp_v4_send_reset",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "tcp_reset_events",
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

func (w *TCP_RST_Woker) setupEventMap() error {
	//eventMap 与解码函数映射
	em, found, err := w.bpfManager.GetMap("tcp_reset_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tcp_reset_events")
	}
	w.eventMap = em
	return nil
}

func (w *TCP_RST_Woker) Start() error {

	// fetch ebpf assets
	buf, err := assets.Asset("ebpf/bin/tcp_reset.o")
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

	// 加载map信息，map对应events decode表。
	err = w.setupEventMap()
	if err != nil {
		return err
	}

	return nil
}

func (w *TCP_RST_Woker) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event TCP_Exception_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return "", err
	}
	return fmt.Sprintf("TCP Reset Event: [%s:%d] -> [%s:%d] \n",
		inet_ntoa(event.Dip), event.Dport,
		inet_ntoa(event.Sip), event.Sport), nil

}

func init() {
	w := &TCP_RST_Woker{}
	w.name = "EBPFTCPRSTProbe"
	Register(w)
}
