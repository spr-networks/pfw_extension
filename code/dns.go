package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"regexp"
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
var DNSTTLCache = map[string][]time.Time{}

// var domainUpdateQueue = []string{}
var DNSCachemtx sync.RWMutex

func handleDnsEvent(topic string, value string) {
	var jsonData DNSRecord
	if err := json.Unmarshal([]byte(value), &jsonData); err != nil {
		log.Println("dns event, invalid json", err)
		return
	}

	domain := ""
	ips := []string{}
	ttls := []int{}

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
						ttls = append(ttls, a.Hdr.Ttl)
					}
				}
			}
		}

		//only handle first query
		break
	}

	if len(ips) != 0 {
		if len(domain) > 1 {
			//get rid if the pesky trailing .
			domain = domain[:len(domain)-1]
			updateDnsCache(domain, ips, ttls)
		}
	}
}

func updateDnsCache(domain string, ips []string, ttls []int) {
	DNSCachemtx.Lock()
	defer DNSCachemtx.Unlock()

	//always percolate domain , ips, and ttls to the regexp check
	updateRegexpCachesLocked(domain, ips, ttls)

	cur_domains, exists := DNSCache[domain]
	if !exists {
		//domain that came in was not cached directly,
		// done
		return
	}

	//this is a domain tracked directly,
	// update the ip set and expiration.

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

	//For now we will just replace.
	//In the future we may want to timeout each IP instead.
	//DNS rules will be inherently lossy regardless though

	//update the cache if it differs
	DNSCache[domain] = ips
	//set expiration to current time + refresh interval
	DNSCacheTime[domain] = time.Now().Add(time.Duration(DNSInterval()) * time.Second)
}

func updateRegexpCachesLocked(domain string, ips []string, ttls []int) {
	//the domain that came in will be checked against our known
	//regexp
	for cached_name, _ := range DNSCache {
		is_regexp := cached_name[0] == '/' && len(cached_name) > 2
		if is_regexp {
			re, err := regexp.Compile("^" + cached_name[1:len(cached_name)-1] + "$")
			if err == nil {
				if re.MatchString(domain) { //slice off trailing dot
					setTTLAliveIPsLocked(cached_name, ips, ttls)
				}
			}
		}
	}
}

func setTTLAliveIPsLocked(regexp_domain string, ips []string, ttls []int) {
	//NOTE: we do not expire. the get will expire for us.

	saved_ips := []string{}
	saved_ttls := []time.Time{}
	add_ip := []bool{}

	cached_ips, exists := DNSCache[regexp_domain]
	cached_ttls, exists2 := DNSTTLCache[regexp_domain]

	cur_time := time.Now()
	if exists && exists2 && len(cached_ips) == len(cached_ttls) {
		for j, new_ip := range ips {
			should_add := true
			for i, cur_ip := range cached_ips {
				if cur_ip == new_ip {
					// bump up the TTL time for this IP
					cached_ttls[i] = cur_time.Add(time.Duration(ttls[j]) * time.Second)
					should_add = false
					break
				}
			}

			add_ip = append(add_ip, should_add)
		}

		//update cached ttls
		DNSTTLCache[regexp_domain] = cached_ttls
	}

	for j, new_ip := range ips {
		// no cached ips or was flagged as new
		should_add := len(add_ip) == 0 || add_ip[j]
		if should_add {
			saved_ips = append(saved_ips, new_ip)
			saved_ttls = append(saved_ttls, cur_time.Add(time.Duration(ttls[j])*time.Second))
		}
	}

	//TBD: smtg to consider is a size restriction here.

	cached_ips = append(cached_ips, saved_ips...)
	cached_ttls = append(cached_ttls, saved_ttls...)
	if len(cached_ips) != len(cached_ttls) {
		fmt.Println("set TTLs failed, mismatched lengths", len(cached_ips), len(cached_ttls))
		return
	}

	DNSCache[regexp_domain] = cached_ips
	DNSTTLCache[regexp_domain] = cached_ttls
}

func getTTLAliveIPsLocked(regexp_domain string, cached_ips []string) []string {
	ips := []string{}
	to_evict := []int{}
	cached_ttls, exists := DNSTTLCache[regexp_domain]

	if !exists {
		//no ttl cache -- abort
		fmt.Println("Unexpected TTL cache missing for regexp domain", len(cached_ips))
		return ips
	}

	if len(cached_ttls) != len(cached_ips) {
		//abort
		fmt.Println("Unexpected TTL cache and IP cache length mismatches", len(cached_ttls), len(cached_ips))
		return ips
	}

	cur_time := time.Now()

	for i := range cached_ttls {
		if cached_ttls[i].After(cur_time) {
			//not yet expired, toss it in
			ips = append(ips, cached_ips[i])
		} else {
			to_evict = append(to_evict, i)
		}
	}

	//purge expired entries
	if len(to_evict) != 0 {
		new_ips := []string{}
		new_ttls := []time.Time{}
		for i := range cached_ips {
			skip_it := false
			for _, evict := range to_evict {
				if i == evict {
					skip_it = true
					break
				}
			}

			if !skip_it {
				new_ips = append(new_ips, cached_ips[i])
				new_ttls = append(new_ttls, cached_ttls[i])
			}
		}

		DNSCache[regexp_domain] = new_ips
		DNSTTLCache[regexp_domain] = new_ttls
	}

	return ips
}

func flushDNSCache(addr Address) {
	if addr.Domain == "" {
		return
	}

	DNSCachemtx.Lock()
	delete(DNSCache, addr.Domain)
	delete(DNSCacheTime, addr.Domain)
	delete(DNSTTLCache, addr.Domain)
	DNSCachemtx.Unlock()
}

func isLastDomainLocked(addr Address) bool {
	//need some awareness of where Address is used,
	//this function needs updating when the firewall config struct is changed

	//returns true  if the addr.Domain is no longer defined in the rules,
	// so the cache can purge it

	if addr.Domain == "" {
		return false
	}
	is_last := true

	for _, rule := range gFirewallConfig.ForwardingRules {
		if rule.OriginalDst.Domain == addr.Domain || rule.Dst.Domain == addr.Domain {
			return false
		}
	}

	for _, rule := range gFirewallConfig.BlockRules {
		if rule.Dst.Domain == addr.Domain {
			return false
		}
	}

	return is_last
}
func query(domain string) []string {
	ips := []string{}

	hosts, err := net.LookupIP(domain)
	if err != nil {
		fmt.Println("failed to look up domain "+domain, err)
	} else {
		for _, ip := range hosts {
			ipv4 := ip.To4()
			if ipv4 != nil {
				ips = append(ips, ipv4.String())
			}
		}
	}

	DNSCachemtx.Lock()
	defer DNSCachemtx.Unlock()

	DNSCache[domain] = ips
	//set expiration to current time + refresh interval
	DNSCacheTime[domain] = time.Now().Add(time.Duration(DNSInterval()) * time.Second)

	return ips
}

func isRegexpDomain(addr Address) bool {
	return addr.Domain != "" && addr.Domain[0] == '/'
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

	if addr.Domain == "" {
		return []string{}
	}

	DNSCachemtx.Lock()
	ips, exists := DNSCache[addr.Domain]
	timeout, exists2 := DNSCacheTime[addr.Domain]

	if !isRegexpDomain(addr) {
		DNSCachemtx.Unlock() //dont hold lock for query
		if !exists || !exists2 || timeout.Before(time.Now()) {
			return query(addr.Domain)
		}
		return ips
	} else {
		defer DNSCachemtx.Unlock()
		//regexp pathway requires filtering by TTL
		if !exists {
			//important, if it does not exist, we will cache an empty array
			//so that the regexp is tracked by the event bus handler
			DNSCache[addr.Domain] = []string{}
			return []string{}
		}
		if len(ips) != 0 {
			return getTTLAliveIPsLocked(addr.Domain, ips)
		}
		// return empty.
		return ips
	}
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
