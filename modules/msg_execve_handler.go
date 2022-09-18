package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log"
	"my-bpf/k8s"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type Execve_Msg_Handler struct {
	name string
}

func init() {
	h := &Execve_Msg_Handler{}
	h.name = "mh_sys_enter_execve"
	RegisterMsgHandler(h)
}

func (h *Execve_Msg_Handler) Name() string {
	return h.name
}

func (h *Execve_Msg_Handler) SetupKernelMap(m *ebpf.Map, sd chan k8s.NetAddress, sr chan k8s.NetAddress) error {
	panic("sys execve probe not need update kernel map")
}

func (h *Execve_Msg_Handler) Decode(b []byte) ([]byte, error) {
	var event Sys_Execve_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	msg := NewSysMessage()
	msg.Event = SYS_Execve
	msg.FillEventBase(event.Probe_Event_Base)
	msg.Filename = unix.ByteSliceToString(event.Filename[:])
	msg.Filename += " " + string(bytes.ReplaceAll(event.Args[:event.BuffSize], []byte{0}, []byte{' '}))
	// msg.Filename += " " + unix.ByteSliceToString(event.Args[:])
	jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		log.Printf("log mesaage failed: %s", err.Error())
	}

	return jsonMsg, nil
}
