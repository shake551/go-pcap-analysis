package query

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/likexian/gokit/assert"
	"github.com/likexian/whois"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

type DNSQuery struct {
	ID       uint16    `json:"id"`
	Time     time.Time `json:"time"`
	SrcIP    IP        `json:"src_ip"`
	DstIP    IP        `json:"dst_ip"`
	Question Question  `json:"question"`
	Response Response  `json:"response"`
}

type IP struct {
	IP           net.IP   `json:"ip"`
	Port         int64    `json:"port"`
	Domain       []string `json:"domain"`
	Organization string   `json:"organization"`
	Country      string   `json:"country"`
	AbuseEmail   string   `json:"abuse_email"`
}

type Packet struct {
	ID       int64  `json:"id"`
	Checksum uint16 `json:"checksum"`
	Length   uint16 `json:"length"`
}

type Question struct {
	Packet Packet `json:"packet"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Class  string `json:"class"`
}

type Response struct {
	Packet Packet `json:"packet"`
}

func GetDNSQueryLogs(filePath string, fromOtherIP string) []*DNSQuery {
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

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
				if fromOtherIP != "" {
					if ip.SrcIP.String() == fromOtherIP {
						continue
					}
				}
				q := DNSQuery{
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

					q.SrcIP = IP{
						IP:           ip.SrcIP,
						Port:         int64(udp.SrcPort),
						Domain:       addr,
						Organization: org,
						Country:      country,
						AbuseEmail:   email,
					}

					q.DstIP = IP{
						IP:   ip.DstIP,
						Port: int64(udp.DstPort),
					}

					packetInfo := Packet{
						ID:       i,
						Checksum: udp.Checksum,
						Length:   udp.Length,
					}

					if len(dns.Questions) >= 1 {
						q.Question = Question{
							Packet: packetInfo,
							Name:   string(dns.Questions[0].Name),
							Type:   fmt.Sprintf("%v", dns.Questions[0].Type),
							Class:  fmt.Sprintf("%v", dns.Questions[0].Class),
						}
					}
				}
				queryLogs = append([]*DNSQuery{&q}, queryLogs...)
			}
		}
	}
	sort.Slice(queryLogs, func(i, j int) bool { return queryLogs[i].Time.Before(queryLogs[j].Time) })
	return queryLogs
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

func ToCSV(queryLogs []*DNSQuery) bytes.Buffer {
	var csvContent bytes.Buffer
	for _, q := range queryLogs {
		csvContent.WriteString(q.Time.Format(time.RFC3339) + "\t")

		csvContent.WriteString(q.SrcIP.IP.String() + "\t" + strconv.FormatInt(q.SrcIP.Port, 10) + "\t")

		csvContent.WriteString(fmt.Sprintf("%v\t", q.SrcIP.Domain))
		csvContent.WriteString(q.SrcIP.Organization + "\t")
		csvContent.WriteString(q.SrcIP.Country + "\t")
		csvContent.WriteString(q.SrcIP.AbuseEmail + "\t")

		csvContent.WriteString(q.DstIP.IP.String() + "\t" + strconv.FormatInt(q.DstIP.Port, 10) + "\t")

		csvContent.WriteString(q.Question.Name + "\t")
		csvContent.WriteString(q.Question.Type + "\t")
		csvContent.WriteString(q.Question.Class + "\t")
		csvContent.WriteString(strconv.Itoa(int(q.Question.Packet.Checksum)) + "\t")
		csvContent.WriteString(strconv.Itoa(int(q.Question.Packet.Length)) + "\t")
		csvContent.WriteString(strconv.Itoa(int(q.Question.Packet.ID)) + "\t")

		csvContent.WriteString(strconv.Itoa(int(q.Response.Packet.Checksum)) + "\t")
		csvContent.WriteString(strconv.Itoa(int(q.Response.Packet.Length)) + "\t")
		csvContent.WriteString(strconv.Itoa(int(q.Response.Packet.ID)) + "\t")

		csvContent.WriteString("\n")
	}

	return csvContent
}

func isContain(target string, array []string) bool {
	for _, ele := range array {
		if ele == target {
			return true
		}
	}
	return false
}
