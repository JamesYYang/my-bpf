package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log"

	"golang.org/x/sys/unix"
)

type Connect_Msg_Handler struct {
	name string
}

func init() {
	h := &Connect_Msg_Handler{}
	h.name = "tcp_connect_events"
	RegisterMsgHandler(h)
}

func (h *Connect_Msg_Handler) Name() string {
	return h.name
}

func (h *Connect_Msg_Handler) Decode(b []byte) ([]byte, error) {
	var event Net_Tcp_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	msg := NewMessage()
	if event.Oldstate == TCP_SYN_RECV && event.Newstate == TCP_ESTABLISHED {
		msg.FillEventBase(event.Probe_Event_Base)
		msg.Event = NET_Accept
		msg.NET_SourceIP = inet_btoa(event.Daddr[:4])
		msg.NET_SourcePort = int(event.Dport)
		msg.NET_DestIP = inet_btoa(event.Saddr[:4])
		msg.NET_DestPort = int(event.Sport)
		msg.UtsName = unix.ByteSliceToString(event.UtsName[:])
	} else if event.Oldstate == TCP_CLOSE && event.Newstate == TCP_SYN_SENT {
		msg.FillEventBase(event.Probe_Event_Base)
		msg.Event = NET_Connect
		msg.NET_SourceIP = inet_btoa(event.Saddr[:4])
		msg.NET_SourcePort = int(event.Sport)
		msg.NET_DestIP = inet_btoa(event.Daddr[:4])
		msg.NET_DestPort = int(event.Dport)
		msg.UtsName = unix.ByteSliceToString(event.UtsName[:])
	} else {
		return nil, nil
	}

	jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		log.Printf("log mesaage failed: %s", err.Error())
	}

	return jsonMsg, nil
}
