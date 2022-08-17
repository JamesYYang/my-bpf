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

type TCP_Connect_Woker struct {
	Woker
}

type TCP_Connect_Event struct {
	Saddr    [16]byte
	Daddr    [16]byte
	Sport    uint16
	Dport    uint16
	Family   uint16
	Oldstate uint16
	Newstate uint16
}

const (
	TCP_ESTABLISHED  = 1
	TCP_SYN_SENT     = 2
	TCP_SYN_RECV     = 3
	TCP_FIN_WAIT1    = 4
	TCP_FIN_WAIT2    = 5
	TCP_TIME_WAIT    = 6
	TCP_CLOSE        = 7
	TCP_CLOSE_WAIT   = 8
	TCP_LAST_ACK     = 9
	TCP_LISTEN       = 10
	TCP_CLOSING      = 11
	TCP_NEW_SYN_RECV = 12
	TCP_MAX_STATES   = 13
)

func (w *TCP_Connect_Woker) Name() string {
	return w.name
}

func (w *TCP_Connect_Woker) Init() {
	w.Woker.SetChild(w)
}

func (w *TCP_Connect_Woker) setupManager() {
	w.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "tracepoint/sock/inet_sock_set_state",
				EbpfFuncName:     "tracepoint_inet_sock_set_state",
				AttachToFuncName: "inet_sock_set_state",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "tcp_connect_events",
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

func (w *TCP_Connect_Woker) setupEventMap() error {
	//eventMap 与解码函数映射
	em, found, err := w.bpfManager.GetMap("tcp_connect_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:tcp_connect_events")
	}
	w.eventMap = em
	return nil
}

func (w *TCP_Connect_Woker) Start() error {

	// fetch ebpf assets
	buf, err := assets.Asset("ebpf/bin/tcp_connect.o")
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

func (w *TCP_Connect_Woker) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event TCP_Connect_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return "", err
	}
	if event.Oldstate == TCP_SYN_RECV && event.Newstate == TCP_ESTABLISHED {
		return fmt.Sprintf("TCP Accept Event: [%s:%d] -> [%s:%d] \n",
			inet_btoa(event.Daddr[:4]), event.Dport,
			inet_btoa(event.Saddr[:4]), event.Sport), nil
	} else if event.Oldstate == TCP_CLOSE && event.Newstate == TCP_SYN_SENT {
		return fmt.Sprintf("TCP Connect Event: [%s:%d] -> [%s:%d] \n",
			inet_btoa(event.Saddr[:4]), event.Sport,
			inet_btoa(event.Daddr[:4]), event.Dport), nil
	} else {
		return "", nil
	}

}

func init() {
	w := &TCP_Connect_Woker{}
	w.name = "EBPFTCPConnectProbe"
	Register(w)
}
