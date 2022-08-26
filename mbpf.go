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

	wd, err := modules.NewWorkerDispatch()
	if err != nil {
		log.Printf("Start dispatch error: %v", err)
	} else {
		wd.InitWorkers()
		wd.Run()
	}

	<-stopper

	logger.Println("Received signal, exiting program..")
}
