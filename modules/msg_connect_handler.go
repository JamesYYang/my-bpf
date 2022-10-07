package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"my-bpf/config"
	"my-bpf/k8s"
	"sync"

	"github.com/cilium/ebpf"
)

type Connect_Msg_Handler struct {
	sync.Mutex
	name        string
	excludeComm map[string]bool
	connCache   map[string]int64
}

func init() {
	h := &Connect_Msg_Handler{}
	h.name = "mh_tcp_connect"
	h.connCache = make(map[string]int64)
	RegisterMsgHandler(h)
}

func (h *Connect_Msg_Handler) SetupKernelMap(m *ebpf.Map, w *k8s.Watcher) error {
	panic("Connect probe not need update kernel map")
}

func (h *Connect_Msg_Handler) Name() string {
	return h.name
}

func (h *Connect_Msg_Handler) SetupMsgFilter(c *config.Configuration) {
	h.excludeComm = ParseExcludeComm(c)
}

func (h *Connect_Msg_Handler) Decode(b []byte, w *k8s.Watcher) ([]byte, error) {
	var event Net_Tcp_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	msg := NewNetMessage()
	if event.Oldstate == TCP_SYN_RECV && event.Newstate == TCP_ESTABLISHED {
		msg.FillEventBase(event.Net_Event_Base)
		msg.Event = NET_Accept
	} else if event.Oldstate == TCP_SYN_SENT && event.Newstate == TCP_ESTABLISHED {
		msg.FillEventBase(event.Net_Event_Base)
		msg.Event = NET_Connect
	} else if event.Newstate == TCP_CLOSE {
		msg.FillEventBase(event.Net_Event_Base)
		msg.Event = NET_Close
	} else {
		return nil, nil
	}

	if _, ok := h.excludeComm[msg.Comm]; ok {
		return nil, nil
	}

	msg.NET_DestIP = inet_btoa(event.Daddr[:4])
	msg.NET_DestPort = int(event.Dport)
	msg.NET_SourceIP = inet_btoa(event.Saddr[:4])
	msg.NET_SourcePort = int(event.Sport)
	if addr, ok := w.IpCtrl.GetEndpointByIP(msg.NET_SourceIP); ok {
		msg.NET_Source = addr.Host
		msg.NET_SourceSvc = addr.Svc
		msg.NET_SourceNS = addr.NS
	}
	if addr, ok := w.IpCtrl.GetEndpointByIP(msg.NET_DestIP); ok {
		msg.NET_Dest = addr.Host
		msg.NET_DestSvc = addr.Svc
		msg.NET_DestNS = addr.NS
	}

	connKey := fmt.Sprintf("%s:%d->%s:%d", msg.NET_SourceIP, msg.NET_SourcePort, msg.NET_DestIP, msg.NET_DestPort)
	h.Lock()
	if msg.Event == NET_Close {
		if birth, ok := h.connCache[connKey]; ok {
			msg.NET_Life = msg.TS - birth
			delete(h.connCache, connKey)
		}
	} else {
		h.connCache[connKey] = msg.TS
	}
	h.Unlock()

	jsonMsg, err := json.Marshal(msg)
	return jsonMsg, err

	// strMsg := fmt.Sprintf("[%s] [(%s) %s:%d] -> [(%s) %s:%d]", msg.Event,
	// 	msg.NET_Source, msg.NET_SourceIP, msg.NET_SourcePort,
	// 	msg.NET_Dest, msg.NET_DestIP, msg.NET_DestPort)
	// return []byte(strMsg), nil
}
