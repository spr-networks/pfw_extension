package main

import (
	"encoding/json"
	"log"
)

type DNSRecord struct {
	A           []ARecord
	FirstAnswer string
	FirstName   string
	Local       string
	Q           []QueryRecord
	Remote      string
	Timestamp   string
	Type        string
	Time        string
	Bucket      string
}

type ARecord struct {
	A   string
	Hdr Header
}

type Header struct {
	Class    int
	Name     string
	Rdlength int
	Rrtype   int
	Ttl      int
}

type QueryRecord struct {
	Name   string
	Qclass int
	Qtype  int
}

func refreshDnsRules(query string, answer string) {
	log.Println("query: %s  answer: %s", query, answer)
}

// subscribe to sprbus and store in db
func handleDnsEvent(topic string, value string) {
	var jsonData DNSRecord
	if err := json.Unmarshal([]byte(value), &jsonData); err != nil {
		log.Println("dns event, invalid json", err)
		return
	}

	for _, q := range jsonData.Q {
		if q.Name == "" {
			continue
		}

		if q.Qclass != 1 && q.Qclass != 28 {
			continue
		}
		for _, a := range jsonData.A {
			if a.Hdr.Class != 1 && a.Hdr.Class != 28 {
				continue
			}
			if q.Name != "" && a.A != "" {
				refreshDnsRules(q.Name, a.A)
			}
		}

		//only handle first query
		break
	}
}

func resolve(addr Address) []string {
	if addr.IP != "" {
		return []string{addr.IP}
	}

	return []string{}
}
