package k8s

import (
	"fmt"
	"log"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type (
	ServiceCtroller struct {
		sync.RWMutex
		Services map[string]*ServiceInfo
	}

	ServiceInfo struct {
		sync.Mutex
		Name            string
		Namespace       string
		ResourceVersion string
		Ports           []ServicePortInfo
	}

	ServicePortInfo struct {
		Name       string
		Port       int32
		TargetPort intstr.IntOrString
	}
)

func (s *ServiceCtroller) ServiceChanged(svc *corev1.Service, isDelete bool) {
	key := fmt.Sprintf("%s.%s", svc.Name, svc.Namespace)
	old, ok := s.Services[key]
	if ok && old.ResourceVersion == svc.ResourceVersion {
		return
	}

	s.Lock()
	defer s.Unlock()

	if isDelete {
		log.Printf("service removed: [%s.%s]\n", svc.Name, svc.Namespace)
		delete(s.Services, key)
	} else {
		var newPorts []ServicePortInfo
		for _, svcPort := range svc.Spec.Ports {
			pInfo := ServicePortInfo{
				Name:       svcPort.Name,
				Port:       svcPort.Port,
				TargetPort: svcPort.TargetPort,
			}
			newPorts = append(newPorts, pInfo)
		}
		if !ok {
			if len(newPorts) == 0 {
				return
			}
			log.Printf("service add: [%s.%s]\n", svc.Name, svc.Namespace)
			// log.Printf("port info: %+v", newPorts)
			s.Services[key] = &ServiceInfo{
				Name:            svc.Name,
				Namespace:       svc.Namespace,
				ResourceVersion: svc.ResourceVersion,
				Ports:           newPorts,
			}
		} else {
			log.Printf("service changed: [%s.%s]\n", svc.Name, svc.Namespace)
			old.ResourceVersion = svc.ResourceVersion
			old.Ports = newPorts
		}
	}
}
