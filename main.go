package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	f := flag.String("f", "", "file path")
	fromOtherIP := flag.String("from-other-ip", "", "filter from outside only")

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

	_, file := filepath.Split(*f)
	fileName := strings.Split(file, ".")[0]

	fp, err := os.Create("log/" + fileName + "_created_" + time.Now().Format(time.RFC3339) + ".txt")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	i := 0
	for {
		i++

		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error: ", err)
			continue
		}

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip := ipLayer.(*layers.IPv4)

		if *fromOtherIP != "" {
			if ip.SrcIP.String() == *fromOtherIP {
				continue
			}
		}

		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			if !dns.QR {
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					fp.WriteString(fmt.Sprintln("No.", i))

					udp := udpLayer.(*layers.UDP)
					fp.WriteString(fmt.Sprintf("%s:%d -> %s:%d \n", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort))
					fp.WriteString(fmt.Sprintf("Checksum: %d \n", udp.Checksum))
					fp.WriteString(fmt.Sprintf("Length: %d \n", udp.Length))
					fp.WriteString(fmt.Sprintf("Question: %s %s %s \n", string(dns.Questions[0].Name), dns.Questions[0].Type, dns.Questions[0].Class))

					addr, err := net.LookupAddr(ip.SrcIP.String())
					if err != nil {
						fp.WriteString(fmt.Sprintln("Lookup error: ", err))
					} else {
						fp.WriteString(fmt.Sprintln(addr))
					}
					fp.WriteString(fmt.Sprintln())
				}
			}
		}
	}
}
