package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"my-bpf/config"
	"my-bpf/k8s"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type DNS_Msg_Handler struct {
	name string
}

func init() {
	h := &DNS_Msg_Handler{}
	h.name = "mh_udp_dns"
	RegisterMsgHandler(h)
}

func (h *DNS_Msg_Handler) Name() string {
	return h.name
}

func (h *DNS_Msg_Handler) SetupMsgFilter(c *config.Configuration) {
}

func (h *DNS_Msg_Handler) SetupKernelMap(m *ebpf.Map, w *k8s.Watcher) error {
	panic("tcp reset probe not need update kernel map")
}

func (h *DNS_Msg_Handler) Decode(b []byte, w *k8s.Watcher) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Udp_DNS_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}

	msg := NewDNSMessage()
	msg.Pid = int(event.Pid)
	msg.Comm = unix.ByteSliceToString(event.Comm[:])
	msg.Host = unix.ByteSliceToString(event.Host[:])
	msg.Spend = (event.Ends - event.Starts) / uint64(time.Millisecond)

	jsonMsg, err := json.Marshal(msg)
	return jsonMsg, err
}
