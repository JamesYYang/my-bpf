package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"my-bpf/k8s"

	"github.com/cilium/ebpf"
)

type Connect_Msg_Handler struct {
	name string
}

func init() {
	h := &Connect_Msg_Handler{}
	h.name = "mh_tcp_connect"
	RegisterMsgHandler(h)
}

func (h *Connect_Msg_Handler) SetupKernelMap(m *ebpf.Map, sd chan k8s.NetAddress, sr chan k8s.NetAddress) error {
	panic("Connect probe not need update kernel map")
}

func (h *Connect_Msg_Handler) Name() string {
	return h.name
}

func (h *Connect_Msg_Handler) Decode(b []byte) ([]byte, error) {
	var event Net_Tcp_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	msg := NewNetMessage()
	if event.Oldstate == TCP_SYN_RECV && event.Newstate == TCP_ESTABLISHED {
		msg.FillEventBase(event.Net_Event_Base)
		msg.Event = NET_Accept
		msg.NET_SourceIP = inet_btoa(event.Daddr[:4])
		msg.NET_SourcePort = int(event.Dport)
		msg.NET_DestIP = inet_btoa(event.Saddr[:4])
		msg.NET_DestPort = int(event.Sport)
	} else if event.Oldstate == TCP_CLOSE && event.Newstate == TCP_SYN_SENT {
		msg.FillEventBase(event.Net_Event_Base)
		msg.Event = NET_Connect
		msg.NET_SourceIP = inet_btoa(event.Saddr[:4])
		msg.NET_SourcePort = int(event.Sport)
		msg.NET_DestIP = inet_btoa(event.Daddr[:4])
		msg.NET_DestPort = int(event.Dport)
	} else {
		return nil, nil
	}

	// jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	// if err != nil {
	// 	log.Printf("log mesaage failed: %s", err.Error())
	// }

	// return jsonMsg, nil

	strMsg := fmt.Sprintf("[%s] [%s:%d] -> [%s:%d]", msg.Event,
		msg.NET_SourceIP, msg.NET_SourcePort,
		msg.NET_DestIP, msg.NET_DestPort)
	return []byte(strMsg), nil
}
