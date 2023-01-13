package query

import (
	"github.com/likexian/gokit/assert"
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
