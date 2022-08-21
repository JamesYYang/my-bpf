package modules

import (
	"encoding/json"
	"log"
	"os"

	"golang.org/x/sys/unix"
)

func NewMessage() *BPFMessage {
	msg := &BPFMessage{}
	msg.Host_Name, _ = os.Hostname()
	msg.Host_IP = GetLocalIP()

	return msg
}

func HandlerMessage(msg *BPFMessage) {
	jsonMsg, err := json.MarshalIndent(msg, "", "\t")
	if err != nil {
		log.Printf("log mesaage failed: %s", err.Error())
	}
	log.Println(string(jsonMsg))
}

func (msg *BPFMessage) FillEventBase(eb Probe_Event_Base) {
	msg.Pid = int(eb.Pid)
	msg.Tgid = int(eb.Tgid)
	msg.Ppid = int(eb.Ppid)
	msg.Comm = unix.ByteSliceToString(eb.Comm[:])
}
