package modules

import (
	"log"
	"os"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type IMsgHandler interface {
	Name() string
	Decode(b []byte) ([]byte, error)
	SetupKernelMap(m *ebpf.Map) error
}

var msgHandlers = make(map[string]IMsgHandler)

func RegisterMsgHandler(h IMsgHandler) {
	name := h.Name()
	if _, ok := msgHandlers[name]; !ok {
		log.Printf("Register message handler: %s", name)
		msgHandlers[name] = h
	}
}

func NewMessage() *BPFMessage {
	msg := &BPFMessage{}
	msg.Host_Name, _ = os.Hostname()
	msg.Host_IP = GetLocalIP()

	return msg
}

func (msg *BPFMessage) FillEventBase(eb Probe_Event_Base) {
	msg.TS = eb.TS
	msg.Pid = int(eb.Pid)
	msg.Tgid = int(eb.Tgid)
	msg.Ppid = int(eb.Ppid)
	msg.Comm = unix.ByteSliceToString(eb.Comm[:])
}
