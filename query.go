package query

import (
	"github.com/likexian/gokit/assert"
	"log"
	"net"
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
