package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
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

func (h *TcpReset_Msg_Handler) SetupKernelMap(m *ebpf.Map) error {
	panic("tcp reset probe not need update kernel map")
}

func (h *TcpReset_Msg_Handler) Decode(b []byte) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Net_Socket_Event
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
