package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type Openat_Msg_Handler struct {
	name string
}

func init() {
	h := &Openat_Msg_Handler{}
	h.name = "sys_enter_openat_events"
	RegisterMsgHandler(h)
}

func (h *Openat_Msg_Handler) Name() string {
	return h.name
}

func (h *Openat_Msg_Handler) SetupKernelMap(m *ebpf.Map) error {
	panic("sys openat probe not need update kernel map")
}

func (h *Openat_Msg_Handler) Decode(b []byte) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Sys_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	msg := NewMessage()
	msg.FillEventBase(event.Probe_Event_Base)
	msg.Event = SYS_Openat
	msg.Filename = unix.ByteSliceToString(event.Filename[:])
	msg.UtsName = unix.ByteSliceToString(event.UtsName[:])

	jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		log.Printf("log mesaage failed: %s", err.Error())
	}

	return jsonMsg, nil
}
