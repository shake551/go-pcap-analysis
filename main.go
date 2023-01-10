package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/likexian/gokit/assert"
	"github.com/likexian/whois"
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

	fp, err := os.Create("csv/" + fileName + "_created_" + time.Now().Format(time.RFC3339) + ".csv")
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

		pickUpData := packet.Metadata().Timestamp.Format(time.RFC3339) + "\t"

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
					udp := udpLayer.(*layers.UDP)
					pickUpData += ip.SrcIP.String() + "\t" + udp.SrcPort.String() + "\t"
					addr, err := net.LookupAddr(ip.SrcIP.String())
					if err != nil {
						pickUpData += fmt.Sprintf("Lookup error: %v\t", err)
					} else {
						pickUpData += fmt.Sprintf("%v\t", addr)
					}

					whoisRaw, err := whois.Whois(ip.SrcIP.String())
					if err != nil {
						log.Println(err, ip.SrcIP, i)
					}

					result := ParseWhois(whoisRaw)

					org, ok := result["Organization"]
					if ok {
						pickUpData += org
					}
					pickUpData += "\t"

					country, ok := result["Country"]
					if ok {
						pickUpData += country
					}
					pickUpData += "\t"

					email, ok := result["OrgAbuseEmail"]
					if ok {
						pickUpData += email
					}
					pickUpData += "\t"

					pickUpData += ip.DstIP.String() + "\t" + udp.DstPort.String() + "\t"

					if len(dns.Questions) < 1 {
						pickUpData += "\t\t\t\t\t"
					} else {
						pickUpData += fmt.Sprintf("%s\t%s\t%s\t", string(dns.Questions[0].Name), dns.Questions[0].Type, dns.Questions[0].Class)
						pickUpData += fmt.Sprintf("%d\t", udp.Checksum)
						pickUpData += fmt.Sprintf("%d\t", udp.Length)
					}
					pickUpData += fmt.Sprintf("%v\t", i)

					fp.WriteString(pickUpData)
					fp.WriteString(fmt.Sprintln())
				}
			}
		}
	}
	log.Println("finish")
}

func ParseWhois(whoisRaw string) map[string]string {
	pickUpName := [...]string{
		"Organization",
		"Country",
		"OrgAbuseEmail",
	}

	res := map[string]string{}

	whoisLines := strings.Split(whoisRaw, "\n")
	for i := 0; i < len(whoisLines); i++ {
		line := strings.TrimSpace(whoisLines[i])
		if len(line) < 5 || !strings.Contains(line, ":") {
			continue
		}

		fChar := line[:1]
		if assert.IsContains([]string{"-", "*", "%", ">", ";"}, fChar) {
			continue
		}

		if line[len(line)-1:] == ":" {
			i++
			for ; i < len(whoisLines); i++ {
				thisLine := strings.TrimSpace(whoisLines[i])
				if strings.Contains(thisLine, ":") {
					break
				}
				line += thisLine + ","
			}
			line = strings.Trim(line, ",")
			i--
		}

		lines := strings.SplitN(line, ":", 2)
		if len(lines) < 2 {
			log.Println("there are no lines, ", lines)
			continue
		}

		name := strings.TrimSpace(lines[0])
		value := strings.TrimSpace(lines[1])
		value = strings.TrimSpace(strings.Trim(value, ":"))

		if value == "" {
			continue
		}

		if isContain(name, pickUpName[:]) {
			res[name] = value
		}
	}

	return res
}

func isContain(target string, array []string) bool {
	for _, ele := range array {
		if ele == target {
			return true
		}
	}
	return false
}
