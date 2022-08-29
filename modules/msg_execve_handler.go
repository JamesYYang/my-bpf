package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log"

	"golang.org/x/sys/unix"
)

type Execve_Msg_Handler struct {
	name string
}

func init() {
	h := &Execve_Msg_Handler{}
	h.name = "sys_enter_execve_events"
	RegisterMsgHandler(h)
}

func (h *Execve_Msg_Handler) Name() string {
	return h.name
}

func (h *Execve_Msg_Handler) Decode(b []byte) ([]byte, error) {
	var event Sys_Execve_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	msg := NewMessage()
	msg.Event = SYS_Execve
	msg.FillEventBase(event.Probe_Event_Base)
	msg.Filename = unix.ByteSliceToString(event.Filename[:])
	msg.UtsName = unix.ByteSliceToString(event.UtsName[:])
	msg.Filename += " " + string(bytes.ReplaceAll(event.Args[:event.BufSize], []byte{0}, []byte{' '}))
	jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		log.Printf("log mesaage failed: %s", err.Error())
	}

	return jsonMsg, nil
}
