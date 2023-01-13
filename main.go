package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/k0kubun/pp/v3"
	"github.com/likexian/gokit/assert"
	"github.com/likexian/whois"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

type DNSQuery struct {
	ID       uint16
	Time     time.Time
	SrcIP    IP
	DstIP    IP
	Question Question
	Response Response
}

type IP struct {
	IP           net.IP
	Port         int64
	Domain       []string
	Organization string
	Country      string
	AbuseEmail   string
}

type Packet struct {
	ID       int64
	Checksum uint16
	Length   uint16
}

type Question struct {
	Packet Packet
	Name   string
	Type   string
	Class  string
}

type Response struct {
	Packet Packet
}

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

	//_, file := filepath.Split(*f)
	//fileName := strings.Split(file, ".")[0]

	//fp, err := os.Create("csv/" + fileName + "_created_" + time.Now().Format(time.RFC3339) + ".csv")
	//if err != nil {
	//	log.Fatal(err)
	//}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	i := int64(0)
	var queryLogs []*DNSQuery
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
							queryLog.Response = Response{
								Packet: Packet{
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
				query := DNSQuery{
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

					result := ParseWhois(whoisRaw)

					org, _ := result["Organization"]
					country, _ := result["Country"]
					email, _ := result["OrgAbuseEmail"]

					query.SrcIP = IP{
						IP:           ip.SrcIP,
						Port:         int64(udp.SrcPort),
						Domain:       addr,
						Organization: org,
						Country:      country,
						AbuseEmail:   email,
					}

					query.DstIP = IP{
						IP:   ip.DstIP,
						Port: int64(udp.DstPort),
					}

					packetInfo := Packet{
						ID:       i,
						Checksum: udp.Checksum,
						Length:   udp.Length,
					}

					if len(dns.Questions) >= 1 {
						query.Question = Question{
							Packet: packetInfo,
							Name:   string(dns.Questions[0].Name),
							Type:   fmt.Sprintf("%v", dns.Questions[0].Type),
							Class:  fmt.Sprintf("%v", dns.Questions[0].Class),
						}
					}
				}
				queryLogs = append([]*DNSQuery{&query}, queryLogs...)
			}
		}
	}
	pp.Print(queryLogs)
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
