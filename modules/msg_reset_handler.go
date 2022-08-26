package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log"

	"golang.org/x/sys/unix"
)

type TcpReset_Msg_Handler struct {
	name string
}

func init() {
	h := &TcpReset_Msg_Handler{}
	h.name = "tcp_reset_events"
	RegisterMsgHandler(h)
}

func (h *TcpReset_Msg_Handler) Name() string {
	return h.name
}

func (h *TcpReset_Msg_Handler) Decode(b []byte) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event TCP_Exception_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}

	msg := NewMessage()
	msg.FillEventBase(event.Probe_Event_Base)
	msg.Event = NET_Rest
	msg.NET_SourceIP = inet_ntoa(event.Dip)
	msg.NET_SourcePort = int(event.Dport)
	msg.NET_DestIP = inet_ntoa(event.Sip)
	msg.NET_DestPort = int(event.Sport)
	msg.UtsName = unix.ByteSliceToString(event.UtsName[:])

	jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		log.Printf("log mesaage failed: %s", err.Error())
	}

	return jsonMsg, nil
}
