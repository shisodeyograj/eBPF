//go:build linux
// +build linux

package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
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

	log.Printf("Attached XDP program to iface %q (index %d)", ifaceObj.Name, ifaceObj.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.XdpStatsMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Drop packet count:\n%s", s)
	}
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key netip.Addr
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := key // IPv4 source address in network byte order.
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))
	}
	return sb.String(), iter.Err()
}
