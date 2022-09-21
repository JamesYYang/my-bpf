package k8s

import (
	"fmt"
	"log"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

type (
	EndpointCtroller struct {
		sync.RWMutex
		w         *Watcher
		Endpoints map[string]*EndpointInfo
	}

	EndpointInfo struct {
		Name            string
		Namespace       string
		ResourceVersion string
		Address         []NetAddress
	}
)

func (e *EndpointCtroller) EndpointChanged(endPoint *corev1.Endpoints, isDelete bool) {
	key := fmt.Sprintf("%s.%s", endPoint.Name, endPoint.Namespace)
	old, ok := e.Endpoints[key]
	if ok && old.ResourceVersion == endPoint.ResourceVersion {
		return
	}
	e.Lock()
	defer e.Unlock()

	if ok {
		e.w.IpCtrl.RemoveEndpoint(old.Address)
	}

	if isDelete {
		log.Printf("endpoint removed: [%s.%s]\n", endPoint.Name, endPoint.Namespace)
		delete(e.Endpoints, key)
	} else {
		newAddress := parseSubset(endPoint.Subsets, endPoint.Name, endPoint.Namespace)
		if !ok {
			if len(newAddress) == 0 { //do not add empty address
				return
			}
			log.Printf("endpoint add: [%s.%s]\n", endPoint.Name, endPoint.Namespace)
			// log.Printf("address info: %+v", newAddress)
			e.Endpoints[key] = &EndpointInfo{
				Name:            endPoint.Name,
				Namespace:       endPoint.Namespace,
				ResourceVersion: endPoint.ResourceVersion,
				Address:         newAddress,
			}
		} else {
			log.Printf("endpoint changed: [%s.%s]\n", endPoint.Name, endPoint.Namespace)
			old.ResourceVersion = endPoint.ResourceVersion
			old.Address = newAddress
		}
		e.w.IpCtrl.AddEndpoint(newAddress)
	}
}

func parseSubset(subsets []corev1.EndpointSubset, svc string, ns string) []NetAddress {
	var servers []NetAddress
	for _, subset := range subsets {
		if len(subset.Ports) == 0 { // no port continue next
			break
		}
		for _, addr := range subset.Addresses {
			if addr.TargetRef != nil && addr.TargetRef.Kind == "Pod" {
				pod := NetAddress{
					Host: addr.TargetRef.Name,
					IP:   addr.IP,
					Type: "Pod",
					Svc:  svc,
					NS:   ns,
				}
				servers = append(servers, pod)
			}
		}
	}
	return servers
}
