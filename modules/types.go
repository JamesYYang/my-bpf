package modules

type Probe_Event_Base struct {
	Pid  uint32
	Tgid uint32
	Ppid uint32
	Comm [16]byte
}

type Sys_Event struct {
	Probe_Event_Base
	Filename [256]byte
	UtsName  [65]byte
}

const (
	TCP_ESTABLISHED  = 1
	TCP_SYN_SENT     = 2
	TCP_SYN_RECV     = 3
	TCP_FIN_WAIT1    = 4
	TCP_FIN_WAIT2    = 5
	TCP_TIME_WAIT    = 6
	TCP_CLOSE        = 7
	TCP_CLOSE_WAIT   = 8
	TCP_LAST_ACK     = 9
	TCP_LISTEN       = 10
	TCP_CLOSING      = 11
	TCP_NEW_SYN_RECV = 12
	TCP_MAX_STATES   = 13
)

type TCP_Connect_Event struct {
	Probe_Event_Base
	Saddr    [16]byte
	Daddr    [16]byte
	Sport    uint16
	Dport    uint16
	Family   uint16
	Oldstate uint16
	Newstate uint16
	UtsName  [65]byte
}

type TCP_Exception_Event struct {
	Probe_Event_Base
	Sip     uint32
	Dip     uint32
	Sport   uint16
	Dport   uint16
	UtsName [65]byte
}

const (
	SYS_Execve  = "SYS_Execve"
	SYS_Openat  = "SYS_Openat"
	NET_Retrans = "TCP_RETANSMIT"
	NET_Rest    = "TCP_RESET"
	NET_Accept  = "TCP_ACCEPT"
	NET_Connect = "TCP_CONNECT"
)

type BPFMessage struct {
	Host_Name      string `json:"Host_Name"`
	UtsName        string `json:"UtsName"`
	Host_IP        string `json:"Host_IP"`
	Event          string `json:"Event"`
	Pid            int    `json:"Pid"`
	Tgid           int    `json:"Tgid"`
	Ppid           int    `json:"Ppid"`
	Comm           string `json:"Comm"`
	Filename       string `json:"Filename"`
	NET_SourceIP   string `json:"NET_SourceIP"`
	NET_SourcePort int    `json:"NET_SourcePort"`
	NET_DestIP     string `json:"NET_DestIP"`
	NET_DestPort   int    `json:"NET_DestPort"`
}
