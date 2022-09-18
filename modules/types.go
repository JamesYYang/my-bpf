package modules

type Probe_Event_Base struct {
	Pid     uint32
	Tgid    uint32
	Ppid    uint32
	Comm    [16]byte
	UtsName [64]byte
}

type Sys_Openat_Event struct {
	Probe_Event_Base
	Filename [256]byte
}

type Sys_Execve_Event struct {
	Probe_Event_Base
	Filename [256]byte
	BuffSize uint32
	Args     [10240]byte
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

const (
	MAP_PERF = "PERF"
	MAP_RING = "RING"
)

type Net_Event_Base struct {
	Pid  uint32
	Comm [16]byte
}

type Net_Tcp_Event struct {
	Net_Event_Base
	Saddr    [16]byte
	Daddr    [16]byte
	Sport    uint16
	Dport    uint16
	Family   uint16
	Oldstate uint16
	Newstate uint16
}

type Net_Socket_Event struct {
	Net_Event_Base
	Sip   uint32
	Dip   uint32
	Sport uint16
	Dport uint16
}

type Net_Packet_Event struct {
	Len       uint32
	Ifindex   uint32
	Sip       uint32
	Dip       uint32
	Sport     uint16
	Dport     uint16
	IsIngress bool
}

type Net_DNS_Event struct {
	TS         uint64
	RecordType uint16
	IsMatch    uint8
	Name       [256]byte
}

const (
	SYS_Execve  = "SYS_Execve"
	SYS_Openat  = "SYS_Openat"
	NET_Retrans = "TCP_RETANSMIT"
	NET_Rest    = "TCP_RESET"
	NET_Accept  = "TCP_ACCEPT"
	NET_Connect = "TCP_CONNECT"
	TC_Package  = "TC_Package"
	NET_DNS     = "UDP_DNS"
)

const (
	EBPF_Trace  = "TracePoint"
	EBPF_Kprobe = "Kprobe"
	EBPF_TC     = "TC"
	EBPF_XDP    = "XDP"
)

type BPFSysMessage struct {
	Host_Name string `json:"Host_Name"`
	UtsName   string `json:"UtsName"`
	Host_IP   string `json:"Host_IP"`
	Event     string `json:"Event"`
	Pid       int    `json:"Pid"`
	Tgid      int    `json:"Tgid"`
	Ppid      int    `json:"Ppid"`
	Comm      string `json:"Comm"`
	Filename  string `json:"Filename"`
}

type BPFNetMessage struct {
	Host_Name      string `json:"Host_Name"`
	Host_IP        string `json:"Host_IP"`
	Event          string `json:"Event"`
	Pid            int    `json:"Pid"`
	Comm           string `json:"Comm"`
	NET_SourceIP   string `json:"NET_SourceIP"`
	NET_Source     string `json:"NET_Source"`
	NET_SourcePort int    `json:"NET_SourcePort"`
	NET_DestIP     string `json:"NET_DestIP"`
	NET_Dest       string `json:"NET_Dest"`
	NET_DestPort   int    `json:"NET_DestPort"`
}
