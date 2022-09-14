package k8s

import (
	"strconv"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
)

type EndPointAddress struct {
	Host string
	IP   string
	Port int
}

func parseServiceName(svcName string) string {
	splitNames := strings.Split(svcName, ".")
	svc := svcName
	if len(splitNames) > 2 {
		svc = strings.Join(splitNames[:2], ".")
	}
	return svc
}

func (w *Watcher) GetEndpointAddress(svcName string, servicePort int) (EndPointAddress, bool) {
	svc := parseServiceName(svcName)

	svcPort, ok := w.GetServiceTargetPort(svc, servicePort)
	if !ok {
		return EndPointAddress{}, ok
	}

	podAddress, ok := w.NextServiceEndPoint(svc)
	if !ok {
		return EndPointAddress{}, ok
	}

	for _, epp := range podAddress.Ports {
		if svcPort.TargetPort.String() == epp.Name || svcPort.TargetPort.String() == strconv.Itoa(int(epp.Port)) {
			return EndPointAddress{
				Host: podAddress.Host,
				IP:   podAddress.IP,
				Port: int(epp.Port),
			}, true
		}
	}

	return EndPointAddress{}, false
}

func (w *Watcher) GetServiceTargetPort(svc string, servicePort int) (ServicePortInfo, bool) {
	w.ServiceCtrl.RLock()
	defer w.ServiceCtrl.RUnlock()
	svcInfo, svcOK := w.ServiceCtrl.Services[svc]
	if !svcOK {
		return ServicePortInfo{}, svcOK
	}
	var svcPort ServicePortInfo
	isFind := false
	for _, p := range svcInfo.Ports {
		if p.Port == int32(servicePort) {
			svcPort = p
			isFind = true
			break
		}
	}
	return svcPort, isFind
}

func (w *Watcher) GetServicePort(svc string, servicePort networkingv1.ServiceBackendPort) (ServicePortInfo, bool) {
	w.ServiceCtrl.RLock()
	defer w.ServiceCtrl.RUnlock()
	svcInfo, svcOK := w.ServiceCtrl.Services[svc]
	if !svcOK {
		return ServicePortInfo{}, svcOK
	}
	var svcPort ServicePortInfo
	isFind := false
	for _, p := range svcInfo.Ports {
		if p.Name == servicePort.Name || p.Port == servicePort.Number {
			svcPort = p
			isFind = true
			break
		}
	}
	return svcPort, isFind
}

func (w *Watcher) NextServiceEndPoint(svc string) (PodAddress, bool) {
	w.EndpointCtrl.RLock()
	defer w.EndpointCtrl.RUnlock()
	endpoint, ok := w.EndpointCtrl.Endpoints[svc]
	if !ok {
		return PodAddress{}, ok
	}
	endpoint.Lock()
	defer endpoint.Unlock()
	if len(endpoint.Address) == 0 {
		return PodAddress{}, false
	}
	endpoint.CurrentIndex = endpoint.CurrentIndex + 1
	if endpoint.CurrentIndex >= len(endpoint.Address) {
		endpoint.CurrentIndex = 0
	}
	endPointInfo := endpoint.Address[endpoint.CurrentIndex]
	return endPointInfo, true
}
