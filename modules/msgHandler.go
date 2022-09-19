package modules

import (
	"log"
	"my-bpf/k8s"
	"os"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type IMsgHandler interface {
	Name() string
	Decode(b []byte, w *k8s.Watcher) ([]byte, error)
	SetupKernelMap(m *ebpf.Map, w *k8s.Watcher) error
}

var msgHandlers = make(map[string]IMsgHandler)

func RegisterMsgHandler(h IMsgHandler) {
	name := h.Name()
	if _, ok := msgHandlers[name]; !ok {
		log.Printf("Register message handler: %s", name)
		msgHandlers[name] = h
	}
}

func NewSysMessage() *BPFSysMessage {
	msg := &BPFSysMessage{}
	msg.TS = GetTimestamp()
	msg.Host_Name, _ = os.Hostname()
	msg.Host_IP, _ = GetLocalIP()
	return msg
}

func NewNetMessage() *BPFNetMessage {
	msg := &BPFNetMessage{}
	msg.TS = GetTimestamp()
	msg.Host_Name, _ = os.Hostname()
	msg.Host_IP, _ = GetLocalIP()
	return msg
}

func (msg *BPFSysMessage) FillEventBase(eb Probe_Event_Base) {
	msg.Pid = int(eb.Pid)
	msg.Tgid = int(eb.Tgid)
	msg.Ppid = int(eb.Ppid)
	msg.Comm = unix.ByteSliceToString(eb.Comm[:])
	msg.UtsName = unix.ByteSliceToString(eb.UtsName[:])
}

func (msg *BPFNetMessage) FillEventBase(eb Net_Event_Base) {
	msg.Pid = int(eb.Pid)
	msg.Comm = unix.ByteSliceToString(eb.Comm[:])
}
