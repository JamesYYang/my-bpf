package modules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"my-bpf/config"
	"my-bpf/k8s"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type Capable_Msg_Handler struct {
	name string
	caps []string
}

func init() {
	h := &Capable_Msg_Handler{}
	h.name = "mh_sys_capable"
	h.caps = []string{
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_DAC_READ_SEARCH",
		"CAP_FOWNER",
		"CAP_FSETID",
		"CAP_KILL",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETPCAP",
		"CAP_LINUX_IMMUTABLE",
		"CAP_NET_BIND_SERVIC",
		"CAP_NET_BROADCAST",
		"CAP_NET_ADMIN",
		"CAP_NET_RAW",
		"CAP_IPC_LOCK",
		"CAP_IPC_OWNER",
		"CAP_SYS_MODULE",
		"CAP_SYS_RAWIO",
		"CAP_SYS_CHROOT",
		"CAP_SYS_PTRACE",
		"CAP_SYS_PACCT",
		"CAP_SYS_ADMIN",
		"CAP_SYS_BOOT",
		"CAP_SYS_NICE",
		"CAP_SYS_RESOURCE",
		"CAP_SYS_TIME",
		"CAP_SYS_TTY_CONFIG",
		"CAP_MKNOD",
		"CAP_LEASE",
		"CAP_AUDIT_WRITE",
		"CAP_AUDIT_CONTROL",
		"CAP_SETFCAP",
		"CAP_MAC_OVERRIDE",
		"CAP_MAC_ADMIN",
		"CAP_SYSLOG",
		"CAP_WAKE_ALARM",
		"CAP_BLOCK_SUSPEND",
		"CAP_AUDIT_READ",
		"CAP_PERFMON",
		"CAP_BPF",
	}
	RegisterMsgHandler(h)
}

func (h *Capable_Msg_Handler) Name() string {
	return h.name
}

func (h *Capable_Msg_Handler) SetupMsgFilter(c *config.Configuration) {
}

func (h *Capable_Msg_Handler) SetupKernelMap(m *ebpf.Map, w *k8s.Watcher) error {
	panic("sys openat probe not need update kernel map")
}

func (h *Capable_Msg_Handler) Decode(b []byte, w *k8s.Watcher) ([]byte, error) {
	// Parse the ringbuf event entry into a bpfEvent structure.
	var event Sys_Capable_Event
	if err := binary.Read(bytes.NewBuffer(b), binary.LittleEndian, &event); err != nil {
		return nil, err
	}
	msg := NewCapableMessage()
	msg.Pid = int(event.Pid)
	msg.Uid = int(event.Uid)
	msg.Comm = unix.ByteSliceToString(event.Comm[:])
	msg.Cap = int(event.Cap)
	msg.Audit = int(event.Audit)
	if msg.Cap <= len(h.caps) {
		msg.CapName = h.caps[msg.Cap]
	}

	jsonMsg, err := json.Marshal(msg)
	return jsonMsg, err
}
