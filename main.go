package main

import (
	"fmt"
	"flag"
	"io"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
)

func main() {
	f:= flag.String("f", "", "file path")

	flag.Parse()

	if *f == "" {
		log.Fatal("no file path")
	}

	flag.Parse()

	handle, err := pcap.OpenOffline(*f)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error: ", err)
			continue
		}
		fmt.Println(packet)
	}
}

