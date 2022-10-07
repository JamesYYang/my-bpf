package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"my-bpf/config"
	"my-bpf/k8s"

	"github.com/cilium/ebpf"
)

type UdpConnect_Msg_Handler struct {
	name string
}

func init() {
	h := &UdpConnect_Msg_Handler{}
	h.name = "mh_udp_connect"
	RegisterMsgHandler(h)
}

func (h *UdpConnect_Msg_Handler) Name() string {
	return h.name
}

func (h *UdpConnect_Msg_Handler) SetupMsgFilter(c *config.Configuration) {
}

func (h *UdpConnect_Msg_Handler) SetupKernelMap(m *ebpf.Map, w *k8s.Watcher) error {
	panic("tcp reset probe not need update kernel map")
}

func (h *UdpConnect_Msg_Handler) Decode(b []byte, w *k8s.Watcher) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Net_Udp_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}

	msg := NewNetMessage()
	msg.FillEventBase(event.Net_Event_Base)
	msg.Event = NET_UDP_CONN
	msg.NET_DestIP = inet_ntoa(event.Dip)
	msg.NET_DestPort = int(event.Dport)
	if addr, ok := w.IpCtrl.GetEndpointByIP(msg.NET_DestIP); ok {
		msg.NET_Dest = addr.Host
		msg.NET_DestSvc = addr.Svc
		msg.NET_DestNS = addr.NS
	}
	jsonMsg, err := json.Marshal(msg)
	return jsonMsg, err

	// strMsg := fmt.Sprintf("[%s] [(%s) %s:%d] -> [(%s) %s:%d]", msg.Event,
	// 	msg.NET_Source, msg.NET_SourceIP, msg.NET_SourcePort,
	// 	msg.NET_Dest, msg.NET_DestIP, msg.NET_DestPort)
	// return []byte(strMsg), nil
}
