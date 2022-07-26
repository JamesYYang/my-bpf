package modules

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"my-bpf/config"
	"my-bpf/k8s"

	"github.com/cilium/ebpf"
)

type Tc_Msg_Handler struct {
	name string
}

func init() {
	h := &Tc_Msg_Handler{}
	h.name = "mh_tc_capture"
	RegisterMsgHandler(h)
}

func (h *Tc_Msg_Handler) Name() string {
	return h.name
}

func (h *Tc_Msg_Handler) SetupMsgFilter(c *config.Configuration) {
}

func (h *Tc_Msg_Handler) SetupKernelMap(m *ebpf.Map, w *k8s.Watcher) error {
	panic("tc probe not need update kernel map")
}

func (h *Tc_Msg_Handler) Decode(b []byte, w *k8s.Watcher) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Net_Packet_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}

	msg := NewNetMessage()
	msg.Event = TC_Package
	action := "receive"
	if !event.IsIngress {
		action = "send"
	}
	msg.NET_SourceIP = inet_ntoa(event.Sip)
	msg.NET_SourcePort = int(event.Sport)
	msg.NET_DestIP = inet_ntoa(event.Dip)
	msg.NET_DestPort = int(event.Dport)

	// jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	// if err != nil {
	// 	log.Printf("log mesaage failed: %s", err.Error())
	// }

	// return jsonMsg, nil
	strMsg := fmt.Sprintf("[%s - %s] [%s:%d] -> [%s:%d] (%d bytes on net interface %d)", msg.Event, action,
		msg.NET_SourceIP, msg.NET_SourcePort,
		msg.NET_DestIP, msg.NET_DestPort, event.Len, event.Ifindex)

	return []byte(strMsg), nil
}
