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
		Endpoints map[string]*EndpointInfo
	}

	EndpointInfo struct {
		sync.Mutex
		Name            string
		Namespace       string
		ResourceVersion string
		CurrentIndex    int
		Address         []PodAddress
	}

	PodAddress struct {
		Host  string
		IP    string
		Ports []PodPort
	}

	PodPort struct {
		Name string
		Port int32
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

	if isDelete {
		log.Printf("endpoint removed: [%s.%s]\n", endPoint.Name, endPoint.Namespace)
		delete(e.Endpoints, key)
	} else {
		newAddress := parseSubset(endPoint.Subsets)
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
	}
}

func parseSubset(subsets []corev1.EndpointSubset) []PodAddress {
	var servers []PodAddress
	for _, subset := range subsets {

		if len(subset.Ports) == 0 { // no port continue next
			break
		}
		var ports []PodPort
		for _, p := range subset.Ports {
			if p.Port > 0 {
				ports = append(ports, PodPort{
					Name: p.Name,
					Port: p.Port,
				})
			}
		}

		for _, addr := range subset.Addresses {
			if addr.TargetRef != nil && addr.TargetRef.Kind == "Pod" {
				pod := PodAddress{
					Host:  addr.TargetRef.Name,
					IP:    addr.IP,
					Ports: ports,
				}
				servers = append(servers, pod)
			}
		}
	}
	return servers
}
