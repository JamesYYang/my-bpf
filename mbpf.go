package main

import (
	"log"
	"my-bpf/modules"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
)

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	logger := log.Default()
	logger.Println("mbpf start...")
	logger.Printf("process pid: %d\n", os.Getpid())

	for n, w := range modules.GetWorkers() {
		logger.Printf("start to run %s module", n)
		w.Init()

		// 加载ebpf，挂载到hook点上，开始监听
		go func(worker modules.IWoker) {
			err := worker.Run()
			if err != nil {
				logger.Printf("%v\n", err)
			}
		}(w)
	}

	<-stopper

	logger.Println("Received signal, exiting program..")
}
