package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
)

type Tc_Msg_Handler struct {
	name string
}

func init() {
	h := &Tc_Msg_Handler{}
	h.name = "tc_capture_events"
	RegisterMsgHandler(h)
}

func (h *Tc_Msg_Handler) Name() string {
	return h.name
}

func (h *Tc_Msg_Handler) Decode(b []byte) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Net_Packet_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}

	msg := NewMessage()
	msg.TS = event.TS
	msg.Event = TC_Package
	action := "receive"
	if !event.IsIngress {
		action = "send"
	}
	msg.Filename = fmt.Sprintf("%s package for length %d in eth %d ", action, event.Len, event.Ifindex)
	msg.NET_SourceIP = inet_ntoa(event.Dip)
	msg.NET_SourcePort = int(event.Dport)
	msg.NET_DestIP = inet_ntoa(event.Sip)
	msg.NET_DestPort = int(event.Sport)

	jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		log.Printf("log mesaage failed: %s", err.Error())
	}

	return jsonMsg, nil
}
