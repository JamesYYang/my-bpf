package k8s

import (
	"context"
	"my-bpf/config"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type Watcher struct {
	client       kubernetes.Interface
	EndpointCtrl *EndpointCtroller
	ServiceCtrl  *ServiceCtroller
	readyCount   int32
	onFinish     func()
}

func NewWatcher(c *config.Configuration, onChange func()) *Watcher {
	var config = &rest.Config{}
	var err error
	if c.IsInK8S {
		config, err = rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	} else {
		// for local test, out of k8s
		config, err = clientcmd.BuildConfigFromFlags("", "conf/kube.yaml")
		if err != nil {
			panic(err.Error())
		}
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	return &Watcher{
		client:       client,
		onFinish:     onChange,
		EndpointCtrl: &EndpointCtroller{Endpoints: make(map[string]*EndpointInfo)},
		ServiceCtrl:  &ServiceCtroller{Services: make(map[string]*ServiceInfo)},
	}

}

func (w *Watcher) Run() {

	var endOnce sync.Once
	var svcOnce sync.Once

	factory := informers.NewSharedInformerFactory(w.client, time.Hour)

	onEndPointChange := func(endPoint *corev1.Endpoints, isDelete bool) {
		endOnce.Do(func() { w.onChanged() })
		w.EndpointCtrl.EndpointChanged(endPoint, isDelete)
	}

	onServiceChange := func(svc *corev1.Service, isDelete bool) {
		svcOnce.Do(func() { w.onChanged() })
		w.ServiceCtrl.ServiceChanged(svc, isDelete)
	}

	endpointHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			endPoint := obj.(*corev1.Endpoints)
			onEndPointChange(endPoint, false)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			endPoint := newObj.(*corev1.Endpoints)
			onEndPointChange(endPoint, false)
		},
		DeleteFunc: func(obj interface{}) {
			endPoint := obj.(*corev1.Endpoints)
			onEndPointChange(endPoint, true)
		},
	}

	serviceHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc := obj.(*corev1.Service)
			onServiceChange(svc, false)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			svc := newObj.(*corev1.Service)
			onServiceChange(svc, false)
		},
		DeleteFunc: func(obj interface{}) {
			svc := obj.(*corev1.Service)
			onServiceChange(svc, true)
		},
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		inf := factory.Core().V1().Endpoints().Informer()
		inf.AddEventHandler(endpointHandler)
		inf.Run(context.TODO().Done())
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		inf := factory.Core().V1().Services().Informer()
		inf.AddEventHandler(serviceHandler)
		inf.Run(context.TODO().Done())
		wg.Done()
	}()

	wg.Wait()
}

func (w *Watcher) onChanged() {
	atomic.AddInt32(&w.readyCount, 1)
	if w.readyCount == 2 {
		w.onFinish()
	}
}
