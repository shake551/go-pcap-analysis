package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/likexian/whois"
	"github.com/shake551/go-pcap-analysis"
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

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	i := int64(0)
	var queryLogs []*query.DNSQuery
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

		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			if dns.QR {
				for _, queryLog := range queryLogs {
					if queryLog.ID == dns.ID {
						log.Println("match", queryLog.ID)
						udpLayer := packet.Layer(layers.LayerTypeUDP)
						if udpLayer != nil {
							udp := udpLayer.(*layers.UDP)
							queryLog.Response = query.Response{
								Packet: query.Packet{
									ID:       i,
									Checksum: udp.Checksum,
									Length:   udp.Length,
								},
							}
						}
						break
					}
				}
			} else {
				if *fromOtherIP != "" {
					if ip.SrcIP.String() == *fromOtherIP {
						continue
					}
				}
				q := query.DNSQuery{
					ID:   dns.ID,
					Time: packet.Metadata().Timestamp,
				}

				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp := udpLayer.(*layers.UDP)

					addr, _ := net.LookupAddr(ip.SrcIP.String())

					whoisRaw, err := whois.Whois(ip.SrcIP.String())
					if err != nil {
						log.Println(err, ip.SrcIP, i)
					}

					result := query.ParseWhois(whoisRaw)

					org, _ := result["Organization"]
					country, _ := result["Country"]
					email, _ := result["OrgAbuseEmail"]

					q.SrcIP = query.IP{
						IP:           ip.SrcIP,
						Port:         int64(udp.SrcPort),
						Domain:       addr,
						Organization: org,
						Country:      country,
						AbuseEmail:   email,
					}

					q.DstIP = query.IP{
						IP:   ip.DstIP,
						Port: int64(udp.DstPort),
					}

					packetInfo := query.Packet{
						ID:       i,
						Checksum: udp.Checksum,
						Length:   udp.Length,
					}

					if len(dns.Questions) >= 1 {
						q.Question = query.Question{
							Packet: packetInfo,
							Name:   string(dns.Questions[0].Name),
							Type:   fmt.Sprintf("%v", dns.Questions[0].Type),
							Class:  fmt.Sprintf("%v", dns.Questions[0].Class),
						}
					}
				}
				queryLogs = append([]*query.DNSQuery{&q}, queryLogs...)
			}
		}
	}
	qj, err := json.Marshal(queryLogs)
	if err != nil {
		log.Printf("failed to parse json. err: %v", err)
	}
	log.Println(qj)

	_, file := filepath.Split(*f)
	fileName := strings.Split(file, ".")[0]

	fp, err := os.Create("json/" + fileName + "_created_" + time.Now().Format(time.RFC3339) + ".json")
	if err != nil {
		log.Fatal(err)
	}
	fp.Write(qj)

	log.Println("finish")
}
