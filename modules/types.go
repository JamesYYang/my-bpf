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

type Udp_DNS_Event struct {
	Pid    uint32
	Starts uint64
	Ends   uint64
	Comm   [16]byte
	Host   [256]byte
}

const (
	SYS_Execve  = "SYS_Execve"
	SYS_Openat  = "SYS_Openat"
	NET_Retrans = "TCP_RETANSMIT"
	NET_Rest    = "TCP_RESET"
	NET_Accept  = "TCP_ACCEPT"
	NET_Connect = "TCP_CONNECT"
	NET_Close   = "TCP_CLOSE"
	TC_Package  = "TC_Package"
	NET_DNS     = "UDP_DNS"
)

const (
	EBPF_Trace  = "TracePoint"
	EBPF_Kprobe = "Kprobe"
	EBPF_Uprobe = "Uprobe"
	EBPF_TC     = "TC"
	EBPF_XDP    = "XDP"
)

type BPFSysMessage struct {
	TS        int64  `json:"TS"`
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
	TS             int64  `json:"TS"`
	Host_Name      string `json:"Host_Name"`
	Host_IP        string `json:"Host_IP"`
	Event          string `json:"Event"`
	Pid            int    `json:"Pid"`
	Comm           string `json:"Comm"`
	NET_SourceIP   string `json:"NET_SourceIP"`
	NET_Source     string `json:"NET_Source"`
	NET_SourceSvc  string `json:"NET_SourceSvc"`
	NET_SourceNS   string `json:"NET_SourceNS"`
	NET_SourcePort int    `json:"NET_SourcePort"`
	NET_DestIP     string `json:"NET_DestIP"`
	NET_Dest       string `json:"NET_Dest"`
	NET_DestSvc    string `json:"NET_DestSvc"`
	NET_DestNS     string `json:"NET_DestNS"`
	NET_DestPort   int    `json:"NET_DestPort"`
	NET_Life       int    `json:"NET_Life"`
}

type BPFDNSParseMessage struct {
	TS        int64  `json:"TS"`
	Host_Name string `json:"Host_Name"`
	Host_IP   string `json:"Host_IP"`
	Pid       int    `json:"Pid"`
	Comm      string `json:"Comm"`
	Host      string `json:"Host"`
	Spend     uint64 `json:"Spend"`
}
