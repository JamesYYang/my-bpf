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

func (w *TCP_Connect_Woker) Decode(em *ebpf.Map, b []byte) (*BPFMessage, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event TCP_Connect_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	if event.Oldstate == TCP_SYN_RECV && event.Newstate == TCP_ESTABLISHED {
		msg := NewMessage()
		msg.FillEventBase(event.Probe_Event_Base)
		msg.Event = NET_Accept
		msg.NET_SourceIP = inet_btoa(event.Daddr[:4])
		msg.NET_SourcePort = int(event.Dport)
		msg.NET_DestIP = inet_btoa(event.Saddr[:4])
		msg.NET_DestPort = int(event.Sport)
		msg.UtsName = unix.ByteSliceToString(event.UtsName[:])
		return msg, nil
	} else if event.Oldstate == TCP_CLOSE && event.Newstate == TCP_SYN_SENT {
		msg := NewMessage()
		msg.FillEventBase(event.Probe_Event_Base)
		msg.Event = NET_Connect
		msg.NET_SourceIP = inet_btoa(event.Saddr[:4])
		msg.NET_SourcePort = int(event.Sport)
		msg.NET_DestIP = inet_btoa(event.Daddr[:4])
		msg.NET_DestPort = int(event.Dport)
		msg.UtsName = unix.ByteSliceToString(event.UtsName[:])
		return msg, nil
	} else {
		return nil, nil
	}
}

func init() {
	w := &TCP_Connect_Woker{}
	w.name = "EBPFTCPConnectProbe"
	Register(w)
}
