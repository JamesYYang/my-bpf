package k8s

import (
	"net"
	"sync"
)

type IpAddressCtroller struct {
	sync.RWMutex
	w           *Watcher
	K8SNodeCIDR string
	ipNet       *net.IPNet
	Ips         map[string]*NetAddress
}

type NetAddress struct {
	Host string `yaml:"Host"`
	IP   string `yaml:"IP"`
	Type string `yaml:"Type"`
	Svc  string `yaml:"Svc"`
	NS   string `yaml:"NS"`
}

func (ipc *IpAddressCtroller) RemoveEndpoint(addr []NetAddress) {
	ipc.Lock()
	defer ipc.Unlock()
	for _, a := range addr {
		if a.Type == "Service" && ipc.w.ServiceRemove != nil {
			ipc.w.ServiceRemove <- a
		}
		delete(ipc.Ips, a.IP)
	}
}

func (ipc *IpAddressCtroller) AddEndpoint(addr []NetAddress) {
	ipc.Lock()
	defer ipc.Unlock()

	if ipc.K8SNodeCIDR != "" && ipc.ipNet == nil {
		ipc.parseNetCIDR()
	}

	for _, a := range addr {
		if a.Type == "Service" && ipc.w.ServiceAdd != nil {
			ipc.w.ServiceAdd <- a
		}

		if ipc.ipNet != nil && ipc.isK8SNode(a.IP) {
			return
		}

		ipc.Ips[a.IP] = &NetAddress{
			Host: a.Host,
			IP:   a.IP,
			Type: a.Type,
			Svc:  a.Svc,
			NS:   a.NS,
		}
	}
}

func (ipc *IpAddressCtroller) GetEndpointByIP(ip string) (*NetAddress, bool) {
	ipc.RLock()
	defer ipc.RUnlock()
	i, ok := ipc.Ips[ip]
	return i, ok
}

func (ipc *IpAddressCtroller) parseNetCIDR() {
	if _, ipnet, err := net.ParseCIDR(ipc.K8SNodeCIDR); err == nil {
		ipc.ipNet = ipnet
	} else {
		ipc.K8SNodeCIDR = ""
	}
}

func (ipc *IpAddressCtroller) isK8SNode(ip string) bool {
	if ipaddr := net.ParseIP(ip); ipaddr != nil {
		return ipc.ipNet.Contains(ipaddr)
	}
	return false
}
