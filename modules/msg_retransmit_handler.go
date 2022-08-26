package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log"

	"golang.org/x/sys/unix"
)

type TcpRetrans_Msg_Handler struct {
	name string
}

func init() {
	h := &TcpRetrans_Msg_Handler{}
	h.name = "tcp_retrans_events"
	RegisterMsgHandler(h)
}

func (h *TcpRetrans_Msg_Handler) Name() string {
	return h.name
}

func (h *TcpRetrans_Msg_Handler) Decode(b []byte) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event TCP_Exception_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	msg := NewMessage()
	msg.FillEventBase(event.Probe_Event_Base)
	msg.Event = NET_Retrans
	msg.NET_SourceIP = inet_ntoa(event.Sip)
	msg.NET_SourcePort = int(event.Sport)
	msg.NET_DestIP = inet_ntoa(event.Dip)
	msg.NET_DestPort = int(event.Dport)
	msg.UtsName = unix.ByteSliceToString(event.UtsName[:])

	jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		log.Printf("log mesaage failed: %s", err.Error())
	}

	return jsonMsg, nil
}
