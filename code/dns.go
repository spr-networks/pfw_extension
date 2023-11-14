package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"
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

var DNSCache = map[string][]string{}
var DNSCacheTime = map[string]time.Time{}

// var domainUpdateQueue = []string{}
var DNSCachemtx sync.RWMutex

/*
func markDNSRebuild(domain string) {
	DNSCachemtx.Lock()
	defer DNSCachemtx.Unlock()

	domainUpdateQueue = append(domainUpdateQueue, domain)
}
*/

// subscribe to sprbus and store in db
func handleDnsEvent(topic string, value string) {
	var jsonData DNSRecord
	if err := json.Unmarshal([]byte(value), &jsonData); err != nil {
		log.Println("dns event, invalid json", err)
		return
	}

	domain := ""
	ips := []string{}

	for _, q := range jsonData.Q {
		if q.Name == "" {
			continue
		}
		domain = q.Name
		if q.Qclass != 1 && q.Qclass != 28 {
			continue
		}

		for _, a := range jsonData.A {
			if a.Hdr.Class != 1 && a.Hdr.Class != 28 {
				continue
			}
			if q.Name != "" && a.A != "" {
				ip := net.ParseIP(a.A)
				if ip != nil {
					if ip.To4() != nil {
						ips = append(ips, ip.To4().String())
					}
				}
			}
		}

		//only handle first query
		break
	}

	DNSCachemtx.Lock()
	defer DNSCachemtx.Unlock()

	cur_domains, exists := DNSCache[domain]
	if !exists {
		//we were not actually tracking this domain already, abort.
		return
	}

	match := true
	if len(cur_domains) == len(ips) {
		sort.Strings(cur_domains)
		sort.Strings(ips)
		for i := range ips {
			if ips[i] != cur_domains[i] {
				match = false
				break
			}
		}
	} else {
		match = false
	}

	//no updates to cache. only bump the timeout.
	if match {
		DNSCacheTime[domain] = time.Now().Add(time.Duration(DNSInterval()) * time.Second)
		return
	}

	//update the cache if it differs
	DNSCache[domain] = ips
	//set expiration to current time + refresh interval
	DNSCacheTime[domain] = time.Now().Add(time.Duration(DNSInterval()) * time.Second)

	//signal to firewall to rebuild?
	//markDNSRebuild(domain)
}

func query(domain string) []string {
	hosts, err := net.LookupIP(domain)
	if err == nil {
		fmt.Println("failed to look up domain "+domain, err)
		return []string{}
	}

	ips := []string{}
	for _, ip := range hosts {
		ipv4 := ip.To4()
		if ipv4 != nil {
			ips = append(ips, ipv4.String())
		}
	}

	DNSCachemtx.Lock()
	defer DNSCachemtx.Unlock()

	DNSCache[domain] = ips
	//set expiration to current time + refresh interval
	DNSCacheTime[domain] = time.Now().Add(time.Duration(DNSInterval()) * time.Second)

	return ips
}

/*
Resolve is designed to do the following:

  - Use the DNSCache of domains if present.

  - If not cached, query it and cache it

  - If it is cached, make sure that its not timed out

    We also use the sprbus to listen for DNS resolutions.
    These resolutions will dynamically update the cache with the latest IP resolutions.
    The prior IPs are not removed. However, they are set with 'timeout' entries in the map.
*/
func resolve(addr Address) []string {
	if addr.IP != "" {
		return []string{addr.IP}
	}
	//domains := []string{}
	DNSCachemtx.Lock()
	ips, exists := DNSCache[addr.Domain]
	timeout, exists2 := DNSCacheTime[addr.Domain]

	/*
		foundInUpdates := false

		if exists && exists2 {
			for i := 0; i < len(domainUpdateQueue); i++ {
				if domainUpdateQueue[i] == addr.Domain {
					// Remove domain from queue
					domainUpdateQueue = append(domainUpdateQueue[:i], domainUpdateQueue[i+1:]...)
					foundInUpdates = true
					break
				}
			}
		}
	*/
	DNSCachemtx.Unlock()

	if !exists || !exists2 || timeout.Before(time.Now()) {
		return query(addr.Domain)
	}

	return ips
}

func DNSInterval() int {
	interval := gFirewallConfig.DNSRefreshInterval
	if interval == 0 {
		return 60 * 5
		// 5 minutes is the default for running a refresh. This is more aggressive than
		// the typical TTL but could be longer. So a user can set their own globally.
		// In the future we can consider per-rule timeouts.
	}
	return interval
}
