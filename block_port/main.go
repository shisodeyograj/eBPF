//go:build linux
// +build linux

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
    "strconv"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

    if err := rlimit.RemoveMemlock(); err != nil {
        panic(err)
    }

    var port string
    fmt.Print("Enter a port: ")
    fmt.Scanln(&port)
    fmt.Println("Port: %s", port)
    portIn, err := strconv.Atoi(port)
    if err != nil {
	    panic(err)
    }

    var objs bpfObjects 
    if err := loadBpfObjects(&objs, nil); err != nil {
        panic(err)
    }
    defer objs.Close() 

    portIn32 := uint32(portIn)
    if err := objs.BpfPortMap.Update(uint32(0), &portIn32, 0); err != nil {
        panic(err)
    }

    interfaceName := "lo"
    ifaceObj, err := net.InterfaceByName(interfaceName)
    if err != nil {
        panic(err)
    }

    link, err := link.AttachXDP(link.XDPOptions{ 
        Program:   objs.BlockPort,
        Interface: ifaceObj.Index,
    })
    if err != nil {
        panic(err)
    }
    defer link.Close() 

    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt)
    log.Printf("Recieving incoming packets on %s..", interfaceName)
    fmt.Println("Press Ctrl+C to stop...")

    // Wait for a signal
    <-stop
    
    fmt.Println("Stopping...")
}
