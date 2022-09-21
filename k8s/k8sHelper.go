package k8s

import (
	"sync"
)

type IpAddressCtroller struct {
	sync.RWMutex
	w       *Watcher
	LocalIP string
	Ips     map[string]*NetAddress
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
	for _, a := range addr {
		if a.Type == "Service" && ipc.w.ServiceAdd != nil {
			ipc.w.ServiceAdd <- a
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
	if ip == ipc.LocalIP {
		return nil, false
	}
	ipc.RLock()
	defer ipc.RUnlock()
	i, ok := ipc.Ips[ip]

	return i, ok
}
