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

type TCP_Retrans_Woker struct {
	Woker
}

type TCP_Retrans_Event struct {
	Sip   uint32
	Dip   uint32
	Sport uint16
	Dport uint16
	State uint8
}

func (w *TCP_Retrans_Woker) Name() string {
	return w.name
}

func (w *TCP_Retrans_Woker) Init() {
	w.Woker.SetChild(w)
}

func (w *TCP_Retrans_Woker) setupManager() {
	w.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				UID:              "MySysTcpRetrans",
				Section:          "kprobe/tcp_retransmit_skb",
				EbpfFuncName:     "kp_tcp_retransmit_skb",
				AttachToFuncName: "tcp_retransmit_skb",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "tcp_retrans_events",
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

func (w *TCP_Retrans_Woker) setupEventMap() error {
	//eventMap 与解码函数映射
	em, found, err := w.bpfManager.GetMap("tcp_retrans_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tcp_retrans_events")
	}
	w.eventMap = em
	return nil
}

func (w *TCP_Retrans_Woker) Start() error {

	// fetch ebpf assets
	buf, err := assets.Asset("ebpf/bin/tcp_retrans.o")
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

func (w *TCP_Retrans_Woker) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event TCP_Retrans_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return "", err
	}
	return fmt.Sprintf("TCP Retransmit Event: [State: %d] [%s:%d] -> [%s:%d] \n",
		event.State,
		inet_ntoa(event.Sip), event.Sport,
		inet_ntoa(event.Dip), event.Dport), nil

}

func init() {
	w := &TCP_Retrans_Woker{}
	w.name = "EBPFTCPRetransProbe"
	Register(w)
}
