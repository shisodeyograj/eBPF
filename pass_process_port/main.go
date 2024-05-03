//go:build linux
// +build linux

package main

import (
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"time"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ifaceName := "lo"
	iface, _ := net.InterfaceByName(ifaceName)

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kprobe, err := link.Kprobe("security_socket_bind", objs.BindIntercept, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprobe.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()
	log.Printf("Listening for events..")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var event bpfInfo
	const key uint32 = 5000
	for range ticker.C {
		if err := objs.Eventmap.Lookup(key, &event); err != nil {
			log.Println("reading map: %v", err)
			continue
		}
		fmt.Printf("\n")
		fmt.Printf("pid: %d\n", event.Pid)
		fmt.Printf("comm: %s\n", unix.ByteSliceToString(event.Comm[:]))
	}
}
