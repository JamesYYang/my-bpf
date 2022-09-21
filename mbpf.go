package main

import (
	"log"
	"my-bpf/k8s"
	"my-bpf/modules"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

var once sync.Once

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	log.Println("mbpf start...")
	log.Printf("process pid: %d\n", os.Getpid())

	localIP, localIF := modules.GetLocalIP()
	log.Printf("local ip: %s on %s\n", localIP, localIF)

	wd, err := modules.NewWorkerDispatch()
	if err != nil {
		log.Printf("Start dispatch error: %v", err)
	} else {
		wd.InitWorkers()
		wd.Run()

		k8sReady := make(chan bool)
		wd.K8SWatcher = k8s.NewWatcher(wd.BPFConfig, localIP, func() {
			once.Do(func() { k8sReady <- true })
		})
		go wd.K8SWatcher.Run()
		<-k8sReady

	}

	<-stopper

	wd.Stop()

	log.Println("Received signal, exiting program..")
}
