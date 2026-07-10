/**
 * Copyright (C) 2022-2023 Supernetworks, Inc - All Rights Reserved
 *
 * This source code is protected under international copyright law.  All rights
 * reserved and protected by the copyright holders.
 * This file is confidential and only available to authorized individuals with the
 * permission of the copyright holders.  If you encounter this file and do not have
 * permission, please contact the copyright holders and delete this file.
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

import (
	"github.com/PaesslerAG/gval"
	cronexpr "github.com/adhocore/gronx"
	"github.com/gorilla/mux"
)

import (
	sprbus "github.com/spr-networks/sprbus-json"
)

var TEST_PREFIX = os.Getenv("TEST_PREFIX")
var UNIX_PLUGIN_LISTENER = TEST_PREFIX + "/state/plugins/pfw/socket"
var FirewallConfigFile = TEST_PREFIX + "/configs/pfw/rules.json"
var DevicesPublicConfigFile = TEST_PREFIX + "/state/public/devices-public.json"
var gAPIInterfacesPublicPath = TEST_PREFIX + "/state/public/interfaces.json"

type PublicInterfaceConfig struct {
	Name    string
	Type    string
	Subtype string
	Enabled bool
}

var FWmtx sync.RWMutex

type ClientIdentifier struct {
	Identity string
	Group    string
	SrcIP    string
	Tag      string
}

type Address struct {
	Domain string
	IP     string
}

type TimeExpression struct {
	CronExpr string // Cron time expression

	// OR

	Start string // Time of Day to start
	End   string // Time of Day to stop (note if End < Start, then rolling over)
	Days  [7]int // Days when to apply TimeStart
}

type PFWRule struct {
	RuleName string
	Client   ClientIdentifier

	Time       TimeExpression
	Expiration int64 //non zero unix time to expire
	Condition  string

	Disabled bool
}

type BlockRule struct {
	PFWRule
	Protocol string
	Dst      Address
	DstPort  string
}

type ForwardingRule struct {
	PFWRule
	Protocol string

	OriginalDst     Address
	OriginalDstPort string

	Dst          Address
	DstPort      string
	DstInterface string
}

type GroupRule struct {
	PFWRule
	Groups []string
}

type TagRule struct {
	PFWRule
	Tags []string
}

type SiteVPN struct {
	Address       string
	PeerPublicKey string
	PublicKey     string
	PrivateKey    string
	PresharedKey  string
	Endpoint      string
	DNS           string
}

type IfaceMarkMapping struct {
	Map  map[string]string //iface -> idx
	rmap map[string]string //idx -> iface, not exported to json, rebuilts
}

// NOTE: be sure to update isLastDomainLocked
// if any new Address structs are introduced
type FirewallConfig struct {
	ForwardingRules    []ForwardingRule
	BlockRules         []BlockRule
	TagRules           []TagRule
	GroupRules         []GroupRule
	Variables          map[string]interface{}
	SiteVPNs           []SiteVPN
	APIToken           string
	IfaceMarkMap       IfaceMarkMapping
	DNSRefreshInterval int
}

var gFirewallConfig = FirewallConfig{[]ForwardingRule{},
	[]BlockRule{},
	[]TagRule{},
	[]GroupRule{},
	map[string]interface{}{},
	[]SiteVPN{},
	"",
	IfaceMarkMapping{},
	0,
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("DEBUGHTTP") != "" {
			fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		}
		handler.ServeHTTP(w, r)
	})
}

func getPFWConfig(w http.ResponseWriter, r *http.Request) {
	loadFirewallRules()

	FWmtx.RLock()
	defer FWmtx.RUnlock()

	x := gFirewallConfig

	x.APIToken = "*masked*"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(x)
}

func saveFirewallRulesLocked() {
	file, _ := json.MarshalIndent(gFirewallConfig, "", " ")
	err := ioutil.WriteFile(FirewallConfigFile, file, 0600)
	if err != nil {
		fmt.Println(err)
	}
}

func loadFirewallRules() error {
	FWmtx.Lock()
	defer FWmtx.Unlock()

	migratePfwRulesIPtoAddress()

	var ret error
	data, err := ioutil.ReadFile(FirewallConfigFile)
	if err != nil {
		ret = err
	} else {
		err := json.Unmarshal(data, &gFirewallConfig)
		if err != nil {
			ret = err
		}
	}

	if gFirewallConfig.IfaceMarkMap.Map == nil {
		gFirewallConfig.IfaceMarkMap.Map = make(map[string]string)
	}

	gFirewallConfig.IfaceMarkMap.rmap = make(map[string]string)

	for entry, value := range gFirewallConfig.IfaceMarkMap.Map {
		gFirewallConfig.IfaceMarkMap.rmap[value] = entry
	}

	return ret
}

var blockVerdict = "goto PFWDROPLOG"
var blockVmapName = "fwd_block"

func validateClientIdentifier(client ClientIdentifier) error {

	count := 0
	if client.Group != "" {
		count += 1
	}
	if client.Tag != "" {
		count += 1
	}
	if client.Identity != "" {
		count += 1
	}
	if client.SrcIP != "" {
		count += 1
	}
	if count != 1 {
		return fmt.Errorf("One parameter is required for the ClientIdentifier")
	}

	if client.SrcIP != "" {
		if CIDRorIP(client.SrcIP) != nil {
			return fmt.Errorf("Invalid SrcIP")
		}
	}

	if client.Identity != "" {
		//check that the identity is in the device
	}

	if client.Group != "" {
		//check that the group is in the device
	}

	if client.Tag != "" {
		//check that the group is in the device
	}

	return nil
}

func validateAddress(addr Address, field string) error {
	if addr.IP != "" {
		if CIDRorIP(addr.IP) != nil {
			return fmt.Errorf("Invalid IP for " + field)
		}
		if addr.Domain != "" {
			return fmt.Errorf("Invalid cant have both IP and Domain for " + field)
		}
	} else if addr.Domain == "" {
		return fmt.Errorf("Need IP or Domain set for " + field)
	} else {
		if addr.Domain[0] == '/' {
			//make sure it ends with / as well
			if len(addr.Domain) < 3 || addr.Domain[len(addr.Domain)-1] != '/' {
				return fmt.Errorf("Invalid regexp for " + field)
			}

			//compile it now
			_, err := regexp.Compile("^" + addr.Domain[1:len(addr.Domain)-1] + "$")
			if err != nil {
				return err
			}
		}
	}

	//more filtered regexp on domain?

	return nil
}

type DeviceEntry struct {
	Name       string
	MAC        string
	WGPubKey   string
	VLANTag    string
	RecentIP   string
	PSKEntry   PSKEntry
	DNSCustom  string
	Groups     []string
	DeviceTags []string
}

type PSKEntry struct {
	Type string
	Psk  string
}

func updateDevice(identity string, entry DeviceEntry) {
	//Ensure PSKEntry is not modified
	entry.PSKEntry.Psk = ""
	entry.PSKEntry.Type = ""

	cli := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

	defer cli.CloseIdleConnections()

	// marshal User to json
	json, err := json.Marshal(entry)
	if err != nil {
		fmt.Println(err)
		return
	}

	req, err := http.NewRequest(http.MethodPut, "http://localhost:80/device?identity="+identity, bytes.NewBuffer(json))
	if err != nil {
		fmt.Println(err)
		return
	}

	FWmtx.RLock()
	token := gFirewallConfig.APIToken
	FWmtx.RUnlock()

	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := cli.Do(req)
	if err != nil {
		fmt.Println("request failed", err)
		return
	}

	defer resp.Body.Close()

}

func siteVPNDNS(iface string) string {
	if !strings.HasPrefix(iface, "site") {
		return ""
	}
	idx, err := strconv.Atoi(iface[len("site"):])
	if err != nil {
		return ""
	}
	FWmtx.RLock()
	defer FWmtx.RUnlock()
	if idx < 0 || idx >= len(gFirewallConfig.SiteVPNs) {
		return ""
	}
	return gFirewallConfig.SiteVPNs[idx].DNS
}

func setDeviceCustomDNS(clientIP, dns string) {
	devices, err := APIDevices()
	if err != nil {
		return
	}
	for identity, dev := range devices {
		if dev.RecentIP == clientIP {
			dev.DNSCustom = dns
			updateDevice(identity, dev)
			return
		}
	}
}

func APIDevices() (map[string]DeviceEntry, error) {
	devs := map[string]DeviceEntry{}

	data, err := ioutil.ReadFile(DevicesPublicConfigFile)
	if err == nil {
		err = json.Unmarshal(data, &devs)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
	} else {
		fmt.Println(err)
		return nil, err
	}

	return devs, nil
}

func clientIPs(client ClientIdentifier) []string {
	//return a list of IPs from a ClientIdentifier
	if client.SrcIP != "" {
		return []string{client.SrcIP}
	}

	devices, err := APIDevices()
	if err != nil {
		fmt.Println("[-] Failed to read devices info")
		return []string{}
	}

	if client.Identity != "" {
		entry, exists := devices[client.Identity]
		if exists {
			if entry.RecentIP != "" {
				return []string{entry.RecentIP}
			}
		}
	}

	if client.Group != "" {
		ips := []string{}

		for _, entry := range devices {
			for _, group := range entry.Groups {
				if group == client.Group && entry.RecentIP != "" {
					ips = append(ips, entry.RecentIP)
					break
				}
			}
		}
		return ips
	}

	if client.Tag != "" {
		ips := []string{}

		for _, entry := range devices {
			for _, tag := range entry.DeviceTags {
				if tag == client.Tag && entry.RecentIP != "" {
					ips = append(ips, entry.RecentIP)
					break
				}
			}
		}
		return ips
	}

	return []string{}
}

// elementTimeout returns the element expiry for DNS-derived addresses

func elementTimeout(addr Address) time.Duration {
	if addr.Domain == "" {
		return 0
	}
	return time.Duration(DNSInterval()) * time.Second
}

func isBlockInstalled(br BlockRule, clientIP string) bool {
	client := GetNFTClient()
	for _, dstIP := range resolve(br.Dst) {
		key, _ := buildIPIPProtocolPortRangeKeys(clientIP, dstIP, br.Protocol, br.DstPort)
		if key == nil {
			return false
		}
		if client.GetMapElement(TableFamilyInet, "filter", blockVmapName, key) != nil {
			return false
		}
	}

	return true
}

func addBlock(br BlockRule, clientIP string) error {
	client := GetNFTClient()
	for _, dstIP := range resolve(br.Dst) {
		key, keyEnd := buildIPIPProtocolPortRangeKeys(clientIP, dstIP, br.Protocol, br.DstPort)

		err := client.AddMapElementRangeWithTimeout(TableFamilyInet, "filter", blockVmapName,
			key, keyEnd, []byte(blockVerdict), elementTimeout(br.Dst))
		if err != nil {
			fmt.Println("failed to add element", err)
			return err
		}
	}
	return nil
}

func deleteBlock(br BlockRule, clientIP string, flushLast bool) error {
	var err error
	client := GetNFTClient()
	for _, dstIP := range resolve(br.Dst) {
		key, keyEnd := buildIPIPProtocolPortRangeKeys(clientIP, dstIP, br.Protocol, br.DstPort)
		if key == nil {
			continue
		}

		err = client.DeleteMapElementRange(TableFamilyInet, "filter", blockVmapName, key, keyEnd)
		if err != nil {
			fmt.Println("failed to delete element", err)
		}
	}

	if flushLast {
		flushDNSCache(br.Dst)
	}

	return err
}

func isForwardingInstalled(fwd ForwardingRule, clientIP string, useCachedOutbound bool) bool {
	client := GetNFTClient()

	if fwd.DstInterface != "" {

		markDst := fwdDstIfaceToIndex(fwd.DstInterface, useCachedOutbound)
		if markDst == "" {
			fmt.Println("[-] PFW could not resolve mark for " + fwd.DstInterface)
			return false
		}

		for _, origDstIP := range resolve(fwd.OriginalDst) {
			var err error
			if fwd.Protocol == "" {
				//if a destination interface is set, only check clientIP and OriginalDstIP
				key, _ := buildIPIPRangeKeys(clientIP, origDstIP)
				err = client.GetMapElement(TableFamilyInet, "mangle", "site_forward_mangle", key)
			} else {
				//when a protocol is set -- add the port as well
				key, _ := buildIPIPPortRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort)
				err = client.GetMapElement(TableFamilyInet, "mangle", "site_forward_"+fwd.Protocol+"_port_mangle", key)
			}

			if err != nil {
				return false
			}
		}
	} else {
		for _, origDstIP := range resolve(fwd.OriginalDst) {
			var err error
			if fwd.OriginalDstPort != "" {
				key, _ := buildIPIPPortRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort)
				err = client.GetMapElement(TableFamilyInet, "nat", "dnat_"+fwd.Protocol+"_ipmap", key)
			} else {
				key, _ := buildIPIPRangeKeys(clientIP, origDstIP)
				err = client.GetMapElement(TableFamilyInet, "nat", "dnat_"+fwd.Protocol+"_anymap", key)
			}

			if err != nil {
				return false
			}
		}
	}
	return true
}

const IfaceMarkMapOffset = 4000
const SiteMarkOffset = 1000
const OutboundRouteTableOffset = 11

func getIfaceMarkMap(iface string) string {
	//expects FWMtx to be held.

	value, exists := gFirewallConfig.IfaceMarkMap.Map[iface]
	if exists {
		return value
	}

	//create one
	i := 0
	for {
		idx := strconv.Itoa(i + IfaceMarkMapOffset)
		_, exists = gFirewallConfig.IfaceMarkMap.rmap[idx]
		if !exists {
			gFirewallConfig.IfaceMarkMap.Map[iface] = idx
			gFirewallConfig.IfaceMarkMap.rmap[idx] = iface
			saveFirewallRulesLocked()
			return idx
		}
		i++
	}
}

func fwdDstIfaceToIndex(iface string, useCachedOutbound bool) string {
	if !strings.HasPrefix(iface, "site") {

		// check if this matches an outbound interface
		outbound := []string{}
		if useCachedOutbound {
			outbound = outboundIfaceCache
		} else {
			outbound = collectOutbound()
		}
		for i, dev := range outbound {
			if dev == iface {
				return strconv.Itoa(i + OutboundRouteTableOffset)
			}
		}
		//no match, use the mark map to make one
		return getIfaceMarkMap(iface)
	}

	val, err := strconv.Atoi(iface[4:])
	if err != nil {
		return ""
	}

	return strconv.Itoa(val + SiteMarkOffset)
}

func addForwarding(fwd ForwardingRule, clientIP string, useCachedOutbound bool) error {
	var err error

	if fwd.DstInterface != "" {
		markDst := fwdDstIfaceToIndex(fwd.DstInterface, useCachedOutbound)
		if markDst == "" {
			fmt.Println("[-] PFW could not resolve mark for " + fwd.DstInterface)
			return fmt.Errorf("[-] Could not resolve mark for " + fwd.DstInterface)
		}

		//ensure mark chain exists
		makeMangleChain(markDst)

		//domains do NOT make sense on fwd.Dst when there is a DstInterace set
		if fwd.Dst.IP != "" {
			makeMarkRouteAndRules(fwd.DstInterface, markDst, fwd.Dst.IP)
		} else {
			makeMarkRouteAndRules(fwd.DstInterface, markDst, "0.0.0.0/0")
		}

		client := GetNFTClient()
		timeout := elementTimeout(fwd.OriginalDst)

		for _, origDstIP := range resolve(fwd.OriginalDst) {

			if fwd.Protocol == "" {
				//if a destination interface is set, only check clientIP and OriginalDstIP

				fkey, fkeyEnd := buildIPIPIfaceRangeKeys(clientIP, origDstIP, fwd.DstInterface)
				client.AddMapElementRangeWithTimeout(TableFamilyInet, "filter", "site_forward",
					fkey, fkeyEnd, []byte("accept"), timeout)

				mkey, mkeyEnd := buildIPIPRangeKeys(clientIP, origDstIP)
				err = client.AddMapElementRangeWithTimeout(TableFamilyInet, "mangle", "site_forward_mangle",
					mkey, mkeyEnd, []byte("jump mark"+markDst), timeout)

			} else {
				//when a protocol is set -- add the port as well
				fkey, fkeyEnd := buildIPIPPortIfaceRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort, fwd.DstInterface)
				client.AddMapElementRangeWithTimeout(TableFamilyInet, "filter", "site_forward_"+fwd.Protocol+"_port",
					fkey, fkeyEnd, []byte("accept"), timeout)

				mkey, mkeyEnd := buildIPIPPortRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort)
				err = client.AddMapElementRangeWithTimeout(TableFamilyInet, "mangle", "site_forward_"+fwd.Protocol+"_port_mangle",
					mkey, mkeyEnd, []byte("jump mark"+markDst), timeout)
			}

			if err != nil {
				fmt.Println("failed to add element", err)
			}

		}
	} else {
		client := GetNFTClient()
		timeout := elementTimeout(fwd.OriginalDst)

		for _, origDstIP := range resolve(fwd.OriginalDst) {
			if fwd.OriginalDstPort != "" {
				key, keyEnd := buildIPIPPortRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort)
				err = client.AddMapElementRangeWithTimeout(TableFamilyInet, "nat", "dnat_"+fwd.Protocol+"_ipmap",
					key, keyEnd, IPToBytes(fwd.Dst.IP), timeout)
				if err != nil {
					fmt.Println("failed to add element", err)
					return err
				}

				err = client.AddMapElementRangeWithTimeout(TableFamilyInet, "nat", "dnat_"+fwd.Protocol+"_portmap",
					key, keyEnd, PortToBytes(fwd.DstPort), timeout)

			} else {
				key, keyEnd := buildIPIPRangeKeys(clientIP, origDstIP)
				err = client.AddMapElementRangeWithTimeout(TableFamilyInet, "nat", "dnat_"+fwd.Protocol+"_anymap",
					key, keyEnd, IPToBytes(fwd.Dst.IP), timeout)
			}

			if err != nil {
				fmt.Println("failed to add element", err)
			}
		}
	}

	if fwd.OriginalDst.IP == "0.0.0.0/0" && strings.HasPrefix(fwd.DstInterface, "site") {
		ip, iface := clientIP, fwd.DstInterface
		go func() {
			if dns := siteVPNDNS(iface); dns != "" {
				setDeviceCustomDNS(ip, dns)
			}
		}()
	}

	return err
}

func deleteForwarding(fwd ForwardingRule, clientIP string, useCachedOutbound bool, flushLast bool) error {
	var err error
	if fwd.DstInterface != "" {
		markDst := fwdDstIfaceToIndex(fwd.DstInterface, useCachedOutbound)
		if markDst == "" {
			fmt.Println("[-] PFW could not resolve mark for " + fwd.DstInterface)
			return fmt.Errorf("[-] Could not resolve mark for " + fwd.DstInterface)
		}

		client := GetNFTClient()

		for _, origDstIP := range resolve(fwd.OriginalDst) {

			if fwd.Protocol == "" {
				//if a destination interface is set, only check clientIP and OriginalDstIP
				fkey, fkeyEnd := buildIPIPIfaceRangeKeys(clientIP, origDstIP, fwd.DstInterface)
				client.DeleteMapElementRange(TableFamilyInet, "filter", "site_forward", fkey, fkeyEnd)

				mkey, mkeyEnd := buildIPIPRangeKeys(clientIP, origDstIP)
				client.DeleteMapElementRange(TableFamilyInet, "mangle", "site_forward_mangle", mkey, mkeyEnd)
			} else {

				fkey, fkeyEnd := buildIPIPPortIfaceRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort, fwd.DstInterface)
				client.DeleteMapElementRange(TableFamilyInet, "filter", "site_forward_"+fwd.Protocol+"_port", fkey, fkeyEnd)

				mkey, mkeyEnd := buildIPIPPortRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort)
				client.DeleteMapElementRange(TableFamilyInet, "mangle", "site_forward_"+fwd.Protocol+"_port_mangle", mkey, mkeyEnd)
			}
		}
	} else {
		client := GetNFTClient()

		for _, origDstIP := range resolve(fwd.OriginalDst) {
			if fwd.OriginalDstPort != "" {
				key, keyEnd := buildIPIPPortRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort)
				err = client.DeleteMapElementRange(TableFamilyInet, "nat", "dnat_"+fwd.Protocol+"_ipmap", key, keyEnd)
				if err != nil {
					fmt.Println("failed to delete element", err)
				}

				err = client.DeleteMapElementRange(TableFamilyInet, "nat", "dnat_"+fwd.Protocol+"_portmap", key, keyEnd)

			} else {
				key, keyEnd := buildIPIPRangeKeys(clientIP, origDstIP)
				err = client.DeleteMapElementRange(TableFamilyInet, "nat", "dnat_"+fwd.Protocol+"_anymap", key, keyEnd)
			}

			if err != nil {
				fmt.Println("failed to delete element", err)
			}
		}
	}

	if flushLast {
		flushDNSCache(fwd.OriginalDst)
	}

	if fwd.OriginalDst.IP == "0.0.0.0/0" && strings.HasPrefix(fwd.DstInterface, "site") {
		ip := clientIP
		go setDeviceCustomDNS(ip, "0")
	}

	return err
}

// https://stackoverflow.com/questions/55093676/checking-if-current-time-is-in-a-given-interval-golang
func inTimeSpan(start, end, check time.Time) bool {
	if start.Before(end) {
		return !check.Before(start) && !check.After(end)
	}
	if start.Equal(end) {
		return check.Equal(start)
	}
	return !start.After(check) || !end.Before(check)
}

// returns true if the current time is matched
// by the time expression
func activeTime(t TimeExpression) bool {

	if t.CronExpr != "" {
		cronChecker := cronexpr.New()
		//had a cron expression to check
		if !cronChecker.IsValid(t.CronExpr) {
			fmt.Println("Invalid cron expression", t.CronExpr)
			return false
		}

		val, err := cronChecker.IsDue(t.CronExpr)
		if err != nil {
			fmt.Println("Invalid cron expression", err.Error())
			return false
		}

		return val
	}

	//NOTE: sunday = 0 in go. america f yeah
	weekday := time.Now().Weekday()
	if t.Days[int(weekday)] == 0 {
		// wrong day of the week
		return false
	}

	t1, err := time.Parse("15:04", t.Start)
	if err != nil {
		fmt.Println("invalid TimeStart", err)
		return false
	}

	t2, err := time.Parse("15:04", t.End)
	if err != nil {
		fmt.Println("invalid TimeEnd", err)
		return false
	}

	check, _ := time.Parse("15:04", time.Now().Format("15:04"))

	return inTimeSpan(t1, t2, check)
}

func timeSet(t TimeExpression) bool {
	if t.CronExpr != "" {
		return true // cron was set
	}

	//time start is set
	if t.Start != "" {
		return true
	}

	// time is not set, do not check time
	return false
}

func checkCondition(condition string) (bool, error) {
	//returns true if the condition matches
	// if there is a problem with the condition, it will return false, err

	value, err := gval.Evaluate(condition, gFirewallConfig.Variables)

	/*
		Helper functions to consider:
			gval.Function("name", func(...))

		- is device in group		:: 				(IP|Device)Has(Group|Tag)(id, value)
		- does device have tag  ::
		- is device connected on wifi	::	(IP|Device)OnWifi(id)
		- is device in arp table			::	(IP|Device)InArp(id)
		- is device connected via vpn	::	(IP|Device)OnVPN(id)
	*/

	if err != nil {
		fmt.Println("invalid rule", err)
		return false, err
	}

	result, ok := value.(bool)
	if !ok {
		fmt.Println("invalid rule, condition is not a boolean", condition)
		return false, fmt.Errorf("condition did not evaluate to a boolean")
	}
	return result, nil
}

func ruleActive(disabled bool, condition string, t TimeExpression, expiry int64) bool {

	if ruleExpired(expiry) {
		return false
	}

	if disabled == true {
		return false
	}

	//if a time is specified and its not active at the current time
	// then the rule is not active
	if timeSet(t) && !activeTime(t) {
		return false
	}

	//check condition variables
	if condition != "" {
		result, _ := checkCondition(condition)
		return result
	}

	return true
}

func ruleExpired(expiry int64) bool {
	if expiry != 0 && expiry < time.Now().Unix() {
		return true
	}
	return false
}

func applyFirewallRulesLocked() {

	//forwarding rules

	refreshForwardOutbound := false
	newOutbound := collectOutbound()
	if !reflect.DeepEqual(newOutbound, outboundIfaceCache) {
		//the list of outbounds changed. All site forwarding needs to be updated
		refreshForwardOutbound = true
	}

	for _, fw := range gFirewallConfig.ForwardingRules {
		for _, clientIP := range clientIPs(fw.Client) {

			if fw.DstInterface != "" && refreshForwardOutbound {
				//delete the old forwarding entry using the cache
				deleteForwarding(fw, clientIP, true, false)
			}

			is_installed := isForwardingInstalled(fw, clientIP, false)
			if ruleActive(fw.Disabled, fw.Condition, fw.Time, fw.Expiration) {
				if !is_installed {
					addForwarding(fw, clientIP, false)
				}
			} else if is_installed {
				deleteForwarding(fw, clientIP, false, false)
			}

		}
	}

	outboundIfaceCache = newOutbound

	//block rules
	for _, br := range gFirewallConfig.BlockRules {
		for _, clientIP := range clientIPs(br.Client) {
			is_installed := isBlockInstalled(br, clientIP)
			if ruleActive(br.Disabled, br.Condition, br.Time, br.Expiration) {
				if !is_installed {
					addBlock(br, clientIP)
				}
			} else if is_installed {
				deleteBlock(br, clientIP, false)
			}

		}
	}

	//tag assignment rules
	for _, rule := range gFirewallConfig.TagRules {
		if ruleActive(rule.Disabled, rule.Condition, rule.Time, rule.Expiration) {
			addClient("tag", rule.Client, rule.Tags)
		} else {
			removeClient("tag", rule.Client, rule.Tags)
		}
	}

	//group assignment rules
	for _, rule := range gFirewallConfig.GroupRules {
		if ruleActive(rule.Disabled, rule.Condition, rule.Time, rule.Expiration) {
			addClient("group", rule.Client, rule.Groups)
		} else {
			removeClient("group", rule.Client, rule.Groups)
		}
	}

	//future: service tags ?
}

func CIDRorIP(IP string) error {
	_, _, err := net.ParseCIDR(IP)
	if err != nil {
		ip := net.ParseIP(IP)
		if ip == nil {
			return err
		} else {
			return nil
		}
	}
	return err
}

func modifyForwardRules(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()

	vars := mux.Vars(r)
	indexStr, index_ok := vars["index"]
	index := 0
	fwd := ForwardingRule{}

	if index_ok {
		val, err := strconv.Atoi(indexStr)
		if err != nil {
			http.Error(w, "invalid index", 400)
			return
		}
		index = val
		if index < 0 || index >= len(gFirewallConfig.ForwardingRules) {
			http.Error(w, "invalid index", 400)
			return
		}
	}

	if index_ok && r.Method == http.MethodDelete {
		//for delete retrieve the existing entry, do not decode.
		fwd = gFirewallConfig.ForwardingRules[index]
	} else {
		err := json.NewDecoder(r.Body).Decode(&fwd)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if fwd.DstInterface != "" {
			dst_idx := fwdDstIfaceToIndex(fwd.DstInterface, false)
			if dst_idx == "" {
				http.Error(w, "Forwarding Interfaces must start with site[0-9]+ or match an active outbound interface ", 400)
				return
			}

			if fwd.DstPort != "" {
				http.Error(w, "When a DstInterface is set, DstPort is not supported", 400)
				return
			}

			if fwd.Protocol != "" && fwd.Protocol != "tcp" && fwd.Protocol != "udp" {
				http.Error(w, "Invalid protocol", 400)
				return
			}

			if fwd.Protocol != "" {

				if fwd.OriginalDstPort == "" {
					fwd.OriginalDstPort = "0-65535"
				}

				re := regexp.MustCompile("^([0-9].*-[0-9].*|[0-9]*)$")

				if !re.MatchString(fwd.OriginalDstPort) {
					http.Error(w, "Invalid OriginalDstPort", 400)
					return
				}
			}

		} else {
			//ports and new DstIp only needed if there is no DstInterface

			if fwd.Protocol != "tcp" && fwd.Protocol != "udp" {
				http.Error(w, "Invalid protocol", 400)
				return
			}

			re := regexp.MustCompile("^([0-9].*-[0-9].*|[0-9]*)$")

			if fwd.DstPort != "" && !re.MatchString(fwd.DstPort) {
				http.Error(w, "Invalid DstPort", 400)
				return
			}

			if fwd.OriginalDstPort != "" && !re.MatchString(fwd.OriginalDstPort) {
				http.Error(w, "Invalid OriginalDstPort", 400)
				return
			}

			//if an OriginalDstPort is set, but a new DstPort is not set, copy
			// it over.
			if fwd.DstPort == "" {
				fwd.DstPort = fwd.OriginalDstPort
			}

			if fwd.Dst.Domain != "" {
				http.Error(w, "Can not use a Domain as the destination", 400)
				return
			}

			err = validateAddress(fwd.Dst, "Dst")
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}

		}

		err = validateClientIdentifier(fwd.Client)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		err = validateAddress(fwd.OriginalDst, "OriginalDst")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.ForwardingRules {
			a := gFirewallConfig.ForwardingRules[i]
			if fwd == a {
				gFirewallConfig.ForwardingRules = append(gFirewallConfig.ForwardingRules[:i], gFirewallConfig.ForwardingRules[i+1:]...)
				saveFirewallRulesLocked()
				is_last := isLastDomainLocked(fwd.OriginalDst)
				FWmtx.Unlock()
				for _, clientIP := range clientIPs(fwd.Client) {
					deleteForwarding(fwd, clientIP, true, is_last)
				}
				FWmtx.Lock()
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	if index_ok {
		//update existing index with the new fwd
		old_fwd := gFirewallConfig.ForwardingRules[index]
		gFirewallConfig.ForwardingRules[index] = fwd
		is_last := isLastDomainLocked(old_fwd.OriginalDst)
		FWmtx.Unlock()
		for _, clientIP := range clientIPs(old_fwd.Client) {
			deleteForwarding(old_fwd, clientIP, true, is_last)
		}
		FWmtx.Lock()
	} else {
		gFirewallConfig.ForwardingRules = append(gFirewallConfig.ForwardingRules, fwd)
	}

	saveFirewallRulesLocked()
}

func modifyBlockRules(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()

	vars := mux.Vars(r)
	indexStr, index_ok := vars["index"]
	index := 0
	br := BlockRule{}

	if index_ok {
		val, err := strconv.Atoi(indexStr)
		if err != nil {
			http.Error(w, "invalid index", 400)
			return
		}
		index = val
		if index < 0 || index >= len(gFirewallConfig.BlockRules) {
			http.Error(w, "invalid index", 400)
			return
		}
	}

	if index_ok && r.Method == http.MethodDelete {
		//for delete retrieve the existing entry, do not decode.
		br = gFirewallConfig.BlockRules[index]
	} else {
		err := json.NewDecoder(r.Body).Decode(&br)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if br.Protocol != "tcp" && br.Protocol != "udp" {
			http.Error(w, "invalid protocol", 400)
			return
		}

		re := regexp.MustCompile("^([0-9].*-[0-9].*|[0-9]*)$")

		if !re.MatchString(br.DstPort) {
			http.Error(w, "Invalid DstPort", 400)
			return
		}

		if br.DstPort == "" {
			//all ports
			br.DstPort = "0-65535"
		}

		err = validateClientIdentifier(br.Client)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		err = validateAddress(br.Dst, "Dst")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

	}

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.BlockRules {
			a := gFirewallConfig.BlockRules[i]
			if br == a {
				gFirewallConfig.BlockRules = append(gFirewallConfig.BlockRules[:i], gFirewallConfig.BlockRules[i+1:]...)
				saveFirewallRulesLocked()
				is_last := isLastDomainLocked(br.Dst)
				FWmtx.Unlock()
				//delete the block rules for the clients where it applies
				for _, clientIP := range clientIPs(br.Client) {
					deleteBlock(br, clientIP, is_last)
				}
				FWmtx.Lock()
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	if index_ok {
		//delete the block rules for the clients where it applies
		old_br := gFirewallConfig.BlockRules[index]
		//update existing index with the new br
		gFirewallConfig.BlockRules[index] = br
		is_last := isLastDomainLocked(old_br.Dst)
		FWmtx.Unlock()
		for _, clientIP := range clientIPs(old_br.Client) {
			deleteBlock(old_br, clientIP, is_last)
		}
		FWmtx.Lock()

	} else {
		gFirewallConfig.BlockRules = append(gFirewallConfig.BlockRules, br)
	}
	saveFirewallRulesLocked()
}

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// generate a new keypair for a client
func genKeyPair() (KeyPair, error) {
	keypair := KeyPair{}

	cmd := exec.Command("wg", "genkey")
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println("wg genkey failed", err)
		return keypair, err
	}

	keypair.PrivateKey = strings.TrimSuffix(string(stdout), "\n")

	cmd = exec.Command("wg", "pubkey")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Println("wg pubkey failed", err)
		return keypair, err
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, keypair.PrivateKey+"\n")
	}()

	pubkey, err := cmd.Output()
	if err != nil {
		fmt.Println("wg pubkey failed: bad key", err)
		return keypair, err
	}

	keypair.PublicKey = strings.TrimSuffix(string(pubkey), "\n")

	return keypair, nil
}

func genPresharedKey() (string, error) {
	cmd := exec.Command("wg", "genpsk")
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println("wg genpsk failed", err)
		return "", err
	}

	PresharedKey := strings.TrimSuffix(string(stdout), "\n")
	return PresharedKey, nil
}

func privateToPubkey(privkey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Println("wg pubkey failed", err)
		return "", err
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, privkey+"\n")
	}()

	pubkey, err := cmd.Output()
	if err != nil {
		fmt.Println("wg pubkey failed: bad key", err)
		return "", err
	}

	return strings.TrimSuffix(string(pubkey), "\n"), nil
}

func modifySiteVPN(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()

	vars := mux.Vars(r)
	indexStr, index_ok := vars["index"]
	index := 0
	vpn := SiteVPN{}

	if index_ok {
		val, err := strconv.Atoi(indexStr)
		if err != nil {
			http.Error(w, "invalid index", 400)
			return
		}
		index = val
		if index < 0 || index >= len(gFirewallConfig.SiteVPNs) {
			http.Error(w, "invalid index", 400)
			return
		}
	}

	if index_ok && r.Method == http.MethodDelete {
		//for delete retrieve the existing entry, do not decode.
		vpn = gFirewallConfig.SiteVPNs[index]
	} else {
		err := json.NewDecoder(r.Body).Decode(&vpn)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if vpn.Address == "" {
			http.Error(w, "Missing Address", 400)
			return
		}

		ip := net.ParseIP(vpn.Address)
		if ip == nil {
			http.Error(w, "Invalid Address", 400)
			return
		}

		if vpn.PeerPublicKey == "" {
			http.Error(w, "Missing PeerPublicKey", 400)
			return
		}

		if vpn.PrivateKey == "" {
			http.Error(w, "Missing PrivateKey", 400)
			return
		}

		if vpn.Endpoint == "" {
			http.Error(w, "Missing Endpoint", 400)
			return
		}

		if vpn.PublicKey == "" {
			vpn.PublicKey, err = privateToPubkey(vpn.PrivateKey)
			if err != nil {
				http.Error(w, "Could not derive PublicKey from PrivateKey: "+err.Error(), 400)
				return
			}
		}

		//optional -> PresharedKey
	}

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.SiteVPNs {
			a := gFirewallConfig.SiteVPNs[i]
			if vpn == a {
				gFirewallConfig.SiteVPNs = append(gFirewallConfig.SiteVPNs[:i], gFirewallConfig.SiteVPNs[i+1:]...)

				//delete interface
				exec.Command("ip", "link", "del", "site"+strconv.Itoa(i)).Run()

				saveFirewallRulesLocked()
				applySiteVPNs()
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	if index_ok {
		gFirewallConfig.SiteVPNs[index] = vpn
	} else {
		gFirewallConfig.SiteVPNs = append(gFirewallConfig.SiteVPNs, vpn)
	}

	applySiteVPNs()

	saveFirewallRulesLocked()
}

func checkSiteVPNIndex(idx int) (SiteVPN, error) {
	vpn := SiteVPN{}

	dataB, err := exec.Command("wg", "showconf", "site"+strconv.Itoa(idx)).Output()
	data := string(dataB)
	if err != nil {
		return vpn, err
	}

	//check that the mark chain exists
	err = CheckChainExists("inet", "mangle", "mark"+strconv.Itoa(idx+SiteMarkOffset))
	if err != nil {
		return vpn, err
	}

	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, "=") {
			pieces := strings.SplitN(line, "=", 2)
			if len(pieces) == 2 {
				pieces[0] = strings.TrimSpace(pieces[0])
				pieces[1] = strings.TrimSpace(pieces[1])
				if pieces[0] == "PrivateKey" {
					vpn.PrivateKey = pieces[1]
				} else if pieces[0] == "Endpoint" {
					vpn.Endpoint = pieces[1]
				} else if pieces[0] == "PublicKey" {
					vpn.PeerPublicKey = pieces[1]
				} else if pieces[0] == "PresharedKey" {
					vpn.PresharedKey = pieces[1]
				}
			}
		}
	}

	//grab public key now
	dataB, err = exec.Command("wg", "show", "site"+strconv.Itoa(idx)).Output()
	data = string(dataB)
	if err != nil {
		return vpn, err
	}
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, "public key:") {
			line = strings.TrimSpace(line)
			pieces := strings.Split(line, "public key: ")
			vpn.PublicKey = strings.TrimSpace(pieces[1])
		}
	}

	//grab ip addr from interface
	dataB, err = exec.Command("ip", "addr", "show", "site"+strconv.Itoa(idx)).Output()
	data = string(dataB)
	if err != nil {
		return vpn, err
	}
	for _, line := range strings.Split(data, "\n") {
		if strings.Contains(line, "inet") {
			line = strings.TrimSpace(line)
			pieces := strings.Split(line, " ")
			if len(pieces) > 2 {
				vpn.Address = strings.Split(pieces[1], "/")[0]
			}
		}
	}

	return vpn, nil
}

func siteConfigPath(i int) string {
	idx := strconv.Itoa(i)
	return TEST_PREFIX + "/configs/pfw/site" + idx + ".conf"
}

func saveSiteConfig(i int, vpn SiteVPN) error {
	filePath := siteConfigPath(i)
	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\n\n", vpn.PrivateKey)
	config += fmt.Sprintf("[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s\n",
		vpn.PeerPublicKey, vpn.Endpoint)

	if vpn.PresharedKey != "" {
		config += fmt.Sprintf("PresharedKey = %s\n", vpn.PresharedKey)
	}

	err := ioutil.WriteFile(filePath, []byte(config), 0600)
	if err != nil {
		return err
	}

	return nil

}

func makeMangleChain(markidx string) error {
	//check nft chain and create it if it does not exist
	err := CheckChainExists("inet", "mangle", "mark"+markidx)
	if err != nil {
		//create it
		err = AddChain("inet", "mangle", "mark"+markidx)
		if err != nil {
			fmt.Println("nft add chain " + markidx + " failed")
			fmt.Println(err)
			return err
		}

		mark, err := strconv.ParseUint(markidx, 10, 32)
		if err == nil {
			err = AddMarkSetRule("inet", "mangle", "mark"+markidx, uint32(mark))
		}
		if err == nil {
			err = AddAcceptRule("inet", "mangle", "mark"+markidx)
		}

		if err != nil {
			//delete the chain
			_ = DeleteChain("inet", "mangle", "mark"+markidx)
			fmt.Println("failed to add rule for mark" + markidx)
			fmt.Println(err)
			return err
		}
	}
	return nil
}

func fwmarkRuleExists(tableIndex string) (bool, error) {

	// Execute the `ip rule show` command to get the list of rules
	out, err := exec.Command("ip", "-4", "rule", "show").CombinedOutput()
	if err != nil {
		return false, err
	}

	index, err := strconv.Atoi(tableIndex)
	if err != nil {
		return false, err
	}

	// Search for the specific rule pattern in the output
	rulePattern := fmt.Sprintf("from all fwmark 0x%x lookup %s", index, tableIndex)
	if strings.Contains(string(out), rulePattern) {
		return true, nil
	}

	return false, nil
}

func makeMarkRouteAndRules(iface string, markidx string, destip_cidr string) error {
	//add policy-based routes

	//flush route table
	exec.Command("ip", "-4", "route", "flush", "table", markidx).Run()

	cmd := exec.Command("ip", "-4", "route", "add", destip_cidr, "dev", iface, "table", markidx)
	if !strings.Contains(destip_cidr, "/") {
		//do a via instead
		cmd = exec.Command("ip", "-4", "route", "add", "default", "via", destip_cidr, "dev", iface, "table", markidx)
	}

	err := cmd.Run()
	if err != nil {
		fmt.Println("failed to add " + iface + " table")
		fmt.Println(err)
		return err
	}

	exists, err := fwmarkRuleExists(markidx)
	if err != nil || !exists {
		err = exec.Command("ip", "-4", "rule", "add", "from", "all", "fwmark", markidx, "table", markidx).Run()
		if err != nil {
			fmt.Println("failed to add " + iface + " fwmark rule")
			fmt.Println(err)
			return err
		}
	}

	return nil
}

func createSiteVPN(i int, vpn SiteVPN) {
	markidx := strconv.Itoa(SiteMarkOffset + i)
	idx := strconv.Itoa(i)

	err := saveSiteConfig(i, vpn)
	if err != nil {
		fmt.Println(err)
		return
	}
	iface := "site" + idx
	err = exec.Command("ip", "link", "add", iface, "type", "wireguard").Run()
	if err != nil {
		fmt.Println("ip link add site" + idx + " failed")
		fmt.Println(err)
		return
	}

	err = exec.Command("wg", "setconf", iface, siteConfigPath(i)).Run()
	if err != nil {
		fmt.Println("wg setconf site" + idx + " failed")
		fmt.Println(err)
		return
	}

	err = exec.Command("ip", "addr", "add", vpn.Address, "dev", iface).Run()
	if err != nil {
		fmt.Println("ip addr add " + vpn.Address + " dev site" + idx + " failed")
		fmt.Println(err)
		return
	}

	err = exec.Command("ip", "link", "set", iface, "up").Run()
	if err != nil {
		fmt.Println("ip link set site" + idx + " up failed")
		fmt.Println(err)
		return
	}

	makeMangleChain(markidx)

	//add default dev as the site idx
	makeMarkRouteAndRules(iface, markidx, "0.0.0.0/0")
}

func applySiteVPNs() {
	FlushSetWithTable("inet", "filter", "outbound_sites")

	for i, siteVPN := range gFirewallConfig.SiteVPNs {
		//check if siteVPN is online and happy. if not, remake it
		iface := "site" + strconv.Itoa(i)
		//add the interface to the outbound_sites set
		AddInterfaceToSet("outbound_sites", iface)

		currentSite, err := checkSiteVPNIndex(i)
		if err == nil && currentSite == siteVPN {
			//configuration matches, all done for this one
			continue
		} else {
			//destroy the interface and re-create it
			exec.Command("ip", "link", "del", iface).Run()
			createSiteVPN(i, siteVPN)

		}
	}
}

func handleVariable(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()

	name := mux.Vars(r)["name"]

	if r.Method == http.MethodGet {
		value, exists := gFirewallConfig.Variables[name]
		if !exists {
			http.Error(w, "Not found", 404)
			return
		}
		json.NewEncoder(w).Encode(value)
		return
	} else if r.Method == http.MethodDelete {
		_, exists := gFirewallConfig.Variables[name]
		if !exists {
			http.Error(w, "Not found", 404)
			return
		}
		delete(gFirewallConfig.Variables, name)
		saveFirewallRulesLocked()
	} else if r.Method == http.MethodPut {
		var value interface{}
		err := json.NewDecoder(r.Body).Decode(&value)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		switch value.(type) {
		case string:
		case float64:
		case bool:
		default:
			vType := fmt.Sprintf("%T", value)
			http.Error(w, "Invalid type: "+vType+". Only strings and numbers are supported", 400)
			return
		}

		gFirewallConfig.Variables[name] = value
		saveFirewallRulesLocked()
	}
}

func testExpression(w http.ResponseWriter, r *http.Request) {
	FWmtx.RLock()
	defer FWmtx.RUnlock()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", 400)
		return
	}

	value, err := checkCondition(string(body))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	json.NewEncoder(w).Encode(value)
}

func ruleTimer() {
	runTimer := func() {
		ticker := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-ticker.C:
				//every 1s check the firewall rules
				FWmtx.Lock()
				applyFirewallRulesLocked()
				FWmtx.Unlock()
			}
		}
	}

	go runTimer()
}

func busListener() {
	go func() {
		for i := 30; i > 0; i-- {
			err := sprbus.HandleEvent("dns:serve:", handleDnsEvent)
			if err != nil {
				log.Println(err)
			}
			time.Sleep(3 * time.Second)
		}
		log.Fatal("failed to establish connection to sprbus")
	}()
}

func matchClient(client ClientIdentifier, entry DeviceEntry, identity string) bool {
	if client.Identity != "" && identity == client.Identity {
		return true
	}

	if client.SrcIP != "" && entry.RecentIP == client.SrcIP {
		return true
	}

	//check groups
	if client.Group != "" {
		for _, group := range entry.Groups {
			if group == client.Group {
				return true
			}
		}
	}

	//check tags
	if client.Tag != "" {
		for _, tag := range entry.DeviceTags {
			if tag == client.Tag {
				return true
			}
		}
	}

	return false
}

func removeClient(property string, client ClientIdentifier, values []string) {

	devices, err := APIDevices()
	if err != nil {
		fmt.Println("[-] Failed to read devices info")
		return
	}

	for identity, entry := range devices {
		if matchClient(client, entry, identity) {

			entry_vals := entry.Groups
			if property == "tag" {
				entry_vals = entry.DeviceTags
			}

			newValues := []string{}

			//for each of the entry values, remove any that match values
			for _, cur_val := range entry_vals {
				keep_value := true
				for _, new_val := range values {
					if new_val == cur_val {
						//found one to remove
						keep_value = false
						break
					}
				}
				if keep_value {
					newValues = append(newValues, cur_val)
				}
			}

			if len(newValues) != len(entry_vals) {
				//a change needs to be made, send update
				if property == "group" {
					entry.Groups = newValues
				} else {
					entry.DeviceTags = newValues
				}
				updateDevice(identity, entry)
			}

		}
	}

}

func addClient(property string, client ClientIdentifier, values []string) {

	devices, err := APIDevices()
	if err != nil {
		fmt.Println("[-] Failed to read devices info")
		return
	}

	for identity, entry := range devices {
		if matchClient(client, entry, identity) {

			entry_vals := entry.Groups
			if property == "tag" {
				entry_vals = entry.DeviceTags
			}

			newValues := entry_vals

			//add any unique new values
			for _, new_val := range values {
				existing_value := false
				for _, cur_val := range entry_vals {
					if new_val == cur_val {
						//already contains this new value
						existing_value = true
						break
					}
				}
				if !existing_value {
					newValues = append(newValues, new_val)
				}
			}

			if len(newValues) != len(entry_vals) {
				//a change needs to be made, send update
				if property == "group" {
					entry.Groups = newValues
				} else {
					entry.DeviceTags = newValues
				}
				updateDevice(identity, entry)
			}

		}
	}

}

func modifyTags(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()

	vars := mux.Vars(r)
	indexStr, index_ok := vars["index"]
	index := 0
	rule := TagRule{}

	if index_ok {
		val, err := strconv.Atoi(indexStr)
		if err != nil {
			http.Error(w, "invalid index", 400)
			return
		}
		index = val
		if index < 0 || index >= len(gFirewallConfig.TagRules) {
			http.Error(w, "invalid index", 400)
			return
		}
	}

	if index_ok && r.Method == http.MethodDelete {
		//for delete retrieve the existing entry, do not decode.
		rule = gFirewallConfig.TagRules[index]
	} else {
		err := json.NewDecoder(r.Body).Decode(&rule)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		err = validateClientIdentifier(rule.Client)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.TagRules {
			a := gFirewallConfig.TagRules[i]
			if reflect.DeepEqual(rule, a) {
				gFirewallConfig.TagRules = append(gFirewallConfig.TagRules[:i], gFirewallConfig.TagRules[i+1:]...)
				saveFirewallRulesLocked()

				FWmtx.Unlock()
				//delete the tag for the clients where it applies
				removeClient("tag", rule.Client, rule.Tags)
				FWmtx.Lock()
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	if index_ok {
		old_rule := gFirewallConfig.TagRules[index]
		gFirewallConfig.TagRules[index] = rule

		FWmtx.Unlock()
		removeClient("tag", old_rule.Client, old_rule.Tags)
		FWmtx.Lock()

	} else {
		gFirewallConfig.TagRules = append(gFirewallConfig.TagRules, rule)
	}
	saveFirewallRulesLocked()
}

func modifyGroups(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()

	vars := mux.Vars(r)
	indexStr, index_ok := vars["index"]
	index := 0
	rule := GroupRule{}

	if index_ok {
		val, err := strconv.Atoi(indexStr)
		if err != nil {
			http.Error(w, "invalid index", 400)
			return
		}
		index = val
		if index < 0 || index >= len(gFirewallConfig.GroupRules) {
			http.Error(w, "invalid index", 400)
			return
		}
	}

	if index_ok && r.Method == http.MethodDelete {
		//for delete retrieve the existing entry, do not decode.
		rule = gFirewallConfig.GroupRules[index]
	} else {
		err := json.NewDecoder(r.Body).Decode(&rule)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		err = validateClientIdentifier(rule.Client)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
	}

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.GroupRules {
			a := gFirewallConfig.GroupRules[i]
			if reflect.DeepEqual(rule, a) {
				gFirewallConfig.GroupRules = append(gFirewallConfig.GroupRules[:i], gFirewallConfig.GroupRules[i+1:]...)
				saveFirewallRulesLocked()

				FWmtx.Unlock()
				//delete the Group for the clients where it applies
				removeClient("group", rule.Client, rule.Groups)
				FWmtx.Lock()
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	if index_ok {
		old_rule := gFirewallConfig.GroupRules[index]
		gFirewallConfig.GroupRules[index] = rule

		FWmtx.Unlock()
		removeClient("group", old_rule.Client, old_rule.Groups)
		FWmtx.Lock()

	} else {
		gFirewallConfig.GroupRules = append(gFirewallConfig.GroupRules, rule)
	}
	saveFirewallRulesLocked()
}

func flushMaps() {
	//start with a clean slate for pfw maps
	for _, entry := range []string{"site_forward", "site_forward_tcp_port", "site_forward_udp_port"} {
		FlushMapByName("inet", "filter", entry)
	}

	for _, entry := range []string{"site_forward_mangle", "site_forward_tcp_port_mangle", "site_forward_udp_port_mangle"} {
		FlushMapByName("inet", "mangle", entry)
	}

	for _, entry := range []string{"dnat_tcp_ipmap", "dnat_tcp_portmap",
		"dnat_tcp_anymap", "dnat_udp_ipmap", "dnat_udp_portmap", "dnat_udp_anymap"} {
		FlushMapByName("inet", "nat", entry)
	}

}

func initPFW() {
	loadFirewallRules()
	applySiteVPNs()
	flushMaps()
	ruleTimer()
	busListener()
	runTasks()
}

//interfaces support

func loadInterfacesPublicConfig() []PublicInterfaceConfig {
	data, err := os.ReadFile(gAPIInterfacesPublicPath)
	config := []PublicInterfaceConfig{}
	if err == nil {
		_ = json.Unmarshal(data, &config)
	}
	return config
}

var outboundIfaceCache = []string{}

func collectOutbound() []string {
	interfaces := loadInterfacesPublicConfig()

	outbound := []string{}
	for _, iface := range interfaces {
		if iface.Type == "Uplink" && iface.Subtype != "pppup" && iface.Enabled {
			outbound = append(outbound, iface.Name)
			if len(outbound) > 128 {
				//rules start at 11. 253/254/255 reserved
				fmt.Println("Too many outbound interfaces, truncating")
				break
			}
		}
	}

	return outbound
}

// minimal mirror of the SPR API topology types (topology.go)
type TopoNode struct {
	ID       string
	Kind     string
	Name     string
	IP       string `json:",omitempty"`
	Iface    string `json:",omitempty"`
	ConnType string `json:",omitempty"`
	Online   bool
}

type TopoEdge struct {
	From  string
	To    string
	Layer string
	Kind  string
}

type TopoSink struct {
	ID     string
	Name   string
	Iface  string
	IP     string `json:",omitempty"`
	Online bool
}

type Topology struct {
	Nodes []TopoNode
	Edges []TopoEdge
	Sinks []TopoSink
}

// advertise site VPN interfaces as routeable sinks
func pluginGetTopology(w http.ResponseWriter, r *http.Request) {
	FWmtx.RLock()
	sites := append([]SiteVPN{}, gFirewallConfig.SiteVPNs...)
	FWmtx.RUnlock()

	if len(sites) == 0 {
		http.Error(w, "no topology", 404)
		return
	}

	topo := Topology{
		Nodes: []TopoNode{{ID: "root", ConnType: "wired", Online: true}},
		Edges: []TopoEdge{},
		Sinks: []TopoSink{},
	}

	for i, vpn := range sites {
		iface := "site" + strconv.Itoa(i)
		online := false
		if link, err := net.InterfaceByName(iface); err == nil {
			online = link.Flags&net.FlagUp != 0
		}
		name := iface
		if vpn.Endpoint != "" {
			name = iface + " (" + vpn.Endpoint + ")"
		}
		topo.Sinks = append(topo.Sinks, TopoSink{ID: iface, Name: name, Iface: iface, Online: online})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topo)
}

func main() {
	unix_plugin_router := mux.NewRouter().StrictSlash(true)

	unix_plugin_router.HandleFunc("/config", getPFWConfig).Methods("GET")
	unix_plugin_router.HandleFunc("/topology", pluginGetTopology).Methods("GET")
	unix_plugin_router.HandleFunc("/block", modifyBlockRules).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/block/{index:[0-9]+}", modifyBlockRules).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/forward", modifyForwardRules).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/forward/{index:[0-9]+}", modifyForwardRules).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/variable/{name}", handleVariable).Methods("DELETE", "GET", "PUT")
	unix_plugin_router.HandleFunc("/testExpression", testExpression).Methods("POST")

	unix_plugin_router.HandleFunc("/tag", modifyTags).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/tag/{index:[0-9]+}", modifyTags).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/group", modifyGroups).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/group/{index:[0-9]+}", modifyGroups).Methods("DELETE", "PUT")

	unix_plugin_router.HandleFunc("/sitevpns", modifySiteVPN).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/sitevpns/{index:[0-9]+}", modifySiteVPN).Methods("DELETE", "PUT")

	unix_plugin_router.HandleFunc("/tasks/run/{task}", runTaskOnce).Methods("PUT")
	unix_plugin_router.HandleFunc("/tasks/configure/{task}", configTask).Methods("PUT")
	unix_plugin_router.HandleFunc("/tasks/config", getTaskConfig).Methods("GET")

	os.Remove(UNIX_PLUGIN_LISTENER)
	unixPluginListener, err := net.Listen("unix", UNIX_PLUGIN_LISTENER)
	if err != nil {
		panic(err)
	}

	pluginServer := http.Server{Handler: logRequest(unix_plugin_router)}

	initPFW()

	pluginServer.Serve(unixPluginListener)
}
