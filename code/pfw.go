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

func atomicWriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := ioutil.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func saveFirewallRulesLocked() {
	data, _ := json.MarshalIndent(gFirewallConfig, "", " ")
	if err := atomicWriteFile(FirewallConfigFile, data); err != nil {
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
			return fmt.Errorf("Invalid IP for %s", field)
		}
		if addr.Domain != "" {
			return fmt.Errorf("Invalid cant have both IP and Domain for %s", field)
		}
	} else if addr.Domain == "" {
		return fmt.Errorf("Need IP or Domain set for %s", field)
	} else {
		if addr.Domain[0] == '/' {
			//make sure it ends with / as well
			if len(addr.Domain) < 3 || addr.Domain[len(addr.Domain)-1] != '/' {
				return fmt.Errorf("Invalid regexp for %s", field)
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

var updateDeviceFunc = updateDevice

func siteVPNDNSLocked(iface string) string {
	if !strings.HasPrefix(iface, "site") {
		return ""
	}
	idx, err := strconv.Atoi(iface[len("site"):])
	if err != nil {
		return ""
	}
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
			updateDeviceFunc(identity, dev)
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

func clientIPsFrom(devices map[string]DeviceEntry, client ClientIdentifier) []string {
	if client.SrcIP != "" {
		return []string{client.SrcIP}
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

type nftElemRef struct {
	table   string
	mapName string
	key     []byte
	keyEnd  []byte
}

func blockElemRefs(br BlockRule, clientIP, dstIP string) []nftElemRef {
	key, keyEnd := buildIPIPProtocolPortRangeKeys(clientIP, dstIP, br.Protocol, br.DstPort)
	if key == nil {
		return nil
	}
	return []nftElemRef{{"filter", blockVmapName, key, keyEnd}}
}

func forwardingElemRefs(fwd ForwardingRule, clientIP, origDstIP string) []nftElemRef {
	if fwd.DstInterface != "" {
		if fwd.Protocol == "" {
			fkey, fkeyEnd := buildIPIPIfaceRangeKeys(clientIP, origDstIP, fwd.DstInterface)
			mkey, mkeyEnd := buildIPIPRangeKeys(clientIP, origDstIP)
			return []nftElemRef{
				{"filter", "site_forward", fkey, fkeyEnd},
				{"mangle", "site_forward_mangle", mkey, mkeyEnd},
			}
		}
		fkey, fkeyEnd := buildIPIPPortIfaceRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort, fwd.DstInterface)
		mkey, mkeyEnd := buildIPIPPortRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort)
		return []nftElemRef{
			{"filter", "site_forward_" + fwd.Protocol + "_port", fkey, fkeyEnd},
			{"mangle", "site_forward_" + fwd.Protocol + "_port_mangle", mkey, mkeyEnd},
		}
	}

	if fwd.OriginalDstPort != "" {
		key, keyEnd := buildIPIPPortRangeKeys(clientIP, origDstIP, fwd.OriginalDstPort)
		return []nftElemRef{
			{"nat", "dnat_" + fwd.Protocol + "_ipmap", key, keyEnd},
			{"nat", "dnat_" + fwd.Protocol + "_portmap", key, keyEnd},
		}
	}

	key, keyEnd := buildIPIPRangeKeys(clientIP, origDstIP)
	return []nftElemRef{{"nat", "dnat_" + fwd.Protocol + "_anymap", key, keyEnd}}
}

func allElemRefsPresent(refs []nftElemRef) bool {
	client := GetNFTClient()
	for _, ref := range refs {
		if client.GetMapElement(TableFamilyInet, ref.table, ref.mapName, ref.key) != nil {
			return false
		}
	}
	return len(refs) != 0
}

func deleteElemRefs(client *NFTClient, refs []nftElemRef) {
	for _, ref := range refs {
		client.DeleteMapElementRange(TableFamilyInet, ref.table, ref.mapName, ref.key, ref.keyEnd)
	}
}

func anyElemRefPresent(refs []nftElemRef) bool {
	client := GetNFTClient()
	for _, ref := range refs {
		if client.GetMapElement(TableFamilyInet, ref.table, ref.mapName, ref.key) == nil {
			return true
		}
	}
	return false
}

func addBlock(br BlockRule, clientIP string) error {
	client := GetNFTClient()
	for _, dstIP := range resolve(br.Dst) {
		refs := blockElemRefs(br, clientIP, dstIP)
		if len(refs) == 0 {
			continue
		}
		err := addElemRefs(client, refs, [][]byte{[]byte(blockVerdict)}, elementTimeout(br.Dst))
		if err != nil {
			fmt.Println("failed to add element", err)
			return err
		}
	}
	return nil
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

func fwdDstIfaceToIndexLocked(iface string) string {
	if !strings.HasPrefix(iface, "site") {

		// check if this matches an outbound interface
		for i, dev := range collectOutbound() {
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

func addForwarding(fwd ForwardingRule, clientIP string) error {
	client := GetNFTClient()
	timeout := elementTimeout(fwd.OriginalDst)

	markDst := ""
	if fwd.DstInterface != "" {
		FWmtx.Lock()
		markDst = fwdDstIfaceToIndexLocked(fwd.DstInterface)
		FWmtx.Unlock()
		if markDst == "" {
			fmt.Println("[-] PFW could not resolve mark for " + fwd.DstInterface)
			return fmt.Errorf("[-] Could not resolve mark for %s", fwd.DstInterface)
		}

		//ensure mark chain exists
		if cerr := makeMangleChain(markDst); cerr != nil {
			return cerr
		}

		routeDst := fwd.Dst.IP
		if routeDst == "" {
			routeDst = "0.0.0.0/0"
		}
		if rerr := makeMarkRouteAndRules(fwd.DstInterface, markDst, routeDst); rerr != nil {
			return rerr
		}
	}

	var err error
	for _, origDstIP := range resolve(fwd.OriginalDst) {
		refs := forwardingElemRefs(fwd, clientIP, origDstIP)

		var values [][]byte
		if fwd.DstInterface != "" {
			values = [][]byte{[]byte("accept"), []byte("jump mark" + markDst)}
		} else if fwd.OriginalDstPort != "" {
			values = [][]byte{IPToBytes(fwd.Dst.IP), PortToBytes(fwd.DstPort)}
		} else {
			values = [][]byte{IPToBytes(fwd.Dst.IP)}
		}

		if aerr := addElemRefs(client, refs, values, timeout); aerr != nil {
			fmt.Println("failed to add element", aerr)
			err = aerr
		}
	}

	return err
}

func addElemRefs(client *NFTClient, refs []nftElemRef, values [][]byte, timeout time.Duration) error {
	for i, ref := range refs {
		err := client.AddMapElementRangeWithTimeout(TableFamilyInet, ref.table, ref.mapName, ref.key, ref.keyEnd, values[i], timeout)
		if err != nil {
			deleteElemRefs(client, refs[:i])
			return err
		}
	}
	return nil
}

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

var reconcileMtx sync.Mutex

func reconcileNow() {
	reconcileMtx.Lock()
	defer reconcileMtx.Unlock()

	cfg := snapshotConfig()

	devices, err := APIDevices()
	if err != nil {
		devices = map[string]DeviceEntry{}
	}

	newOutbound := collectOutbound()
	refreshForwardOutbound := !reflect.DeepEqual(newOutbound, outboundIfaceCache)

	installedForwards = reconcileRules(cfg.ForwardingRules, installedForwards,
		ruleOps[ForwardingRule]{
			clientIPs: func(fw ForwardingRule) []string { return clientIPsFrom(devices, fw.Client) },
			resolve:   func(fw ForwardingRule) []string { return resolve(fw.OriginalDst) },
			active: func(fw ForwardingRule) bool {
				return ruleActive(fw.Disabled, fw.Condition, fw.Time, fw.Expiration)
			},
			refs:    forwardingElemRefs,
			install: func(fw ForwardingRule, clientIP string) { addForwarding(fw, clientIP) },
			needsRebuild: func(fw ForwardingRule) bool {
				return fw.DstInterface != "" && refreshForwardOutbound
			},
		})

	outboundIfaceCache = newOutbound

	installedBlocks = reconcileRules(cfg.BlockRules, installedBlocks,
		ruleOps[BlockRule]{
			clientIPs: func(br BlockRule) []string { return clientIPsFrom(devices, br.Client) },
			resolve:   func(br BlockRule) []string { return resolve(br.Dst) },
			active: func(br BlockRule) bool {
				return ruleActive(br.Disabled, br.Condition, br.Time, br.Expiration)
			},
			refs:    blockElemRefs,
			install: func(br BlockRule, clientIP string) { addBlock(br, clientIP) },
		})

	syncDeviceState(cfg, devices)

	saveInstalledState()
}

type configSnapshot struct {
	ForwardingRules []ForwardingRule
	BlockRules      []BlockRule
	TagRules        []TagRule
	GroupRules      []GroupRule
	SiteDNS         map[string]string //site iface -> DNS server, "" filtered
}

func snapshotConfig() configSnapshot {
	FWmtx.RLock()
	defer FWmtx.RUnlock()

	cfg := configSnapshot{
		ForwardingRules: append([]ForwardingRule{}, gFirewallConfig.ForwardingRules...),
		BlockRules:      append([]BlockRule{}, gFirewallConfig.BlockRules...),
		TagRules:        append([]TagRule{}, gFirewallConfig.TagRules...),
		GroupRules:      append([]GroupRule{}, gFirewallConfig.GroupRules...),
		SiteDNS:         map[string]string{},
	}
	for i := range gFirewallConfig.SiteVPNs {
		if dns := gFirewallConfig.SiteVPNs[i].DNS; dns != "" {
			cfg.SiteDNS[fmt.Sprintf("site%d", i)] = dns
		}
	}
	return cfg
}

func withConfigMutation(h func(w http.ResponseWriter, r *http.Request, changed *bool)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		changed := false
		func() {
			FWmtx.Lock()
			defer FWmtx.Unlock()
			h(w, r, &changed)
		}()
		if changed {
			reconcileNow()
		}
	}
}

type installedRule[R any] struct {
	Rule R
	IPs  map[string]map[string]bool
}

type installedFwd = installedRule[ForwardingRule]
type installedBlk = installedRule[BlockRule]

type ruleOps[R any] struct {
	clientIPs    func(R) []string
	resolve      func(R) []string
	active       func(R) bool
	refs         func(r R, clientIP, dstIP string) []nftElemRef
	install      func(r R, clientIP string)
	needsRebuild func(R) bool
}

func (ops ruleOps[R]) refsFor(r R, clientIP string) func(string) []nftElemRef {
	return func(dstIP string) []nftElemRef { return ops.refs(r, clientIP, dstIP) }
}

func reconcileRules[R any](rules []R, prev map[string]installedRule[R], ops ruleOps[R]) map[string]installedRule[R] {
	keys := make([]string, len(rules))
	for i, r := range rules {
		k, _ := json.Marshal(r)
		keys[i] = string(k)
	}
	desired := listToSet(keys)

	next := map[string]installedRule[R]{}

	for key, entry := range prev {
		if desired[key] {
			continue
		}
		rule := entry.Rule
		leftIPs := map[string]map[string]bool{}
		for clientIP, dstIPs := range entry.IPs {
			if left := deleteElements(ops.refsFor(rule, clientIP), dstIPs); len(left) != 0 {
				leftIPs[clientIP] = left
			}
		}
		if len(leftIPs) != 0 {
			next[key] = installedRule[R]{rule, leftIPs}
		}
	}

	for i, r := range rules {
		key := keys[i]
		tracked := prev[key].IPs
		current := listToSet(ops.clientIPs(r))
		resolved := listToSet(ops.resolve(r))
		active := ops.active(r)
		rebuild := ops.needsRebuild != nil && ops.needsRebuild(r)

		nowIPs := map[string]map[string]bool{}

		for clientIP, dstIPs := range tracked {
			if current[clientIP] {
				continue
			}
			if left := deleteElements(ops.refsFor(r, clientIP), dstIPs); len(left) != 0 {
				nowIPs[clientIP] = left
			}
		}

		for clientIP := range current {
			trackedIPs := tracked[clientIP]
			refsFor := ops.refsFor(r, clientIP)

			if rebuild {
				trackedIPs = deleteElements(refsFor, unionSets(trackedIPs, resolved))
			}

			if active {
				if needsInstall(refsFor, resolved) {
					ops.install(r, clientIP)
				}
				set := cloneSet(resolved)
				for dstIP := range trackedIPs {
					if !set[dstIP] && anyElemRefPresent(refsFor(dstIP)) {
						set[dstIP] = true
					}
				}
				nowIPs[clientIP] = set
			} else {
				if left := deleteElements(refsFor, unionSets(trackedIPs, resolved)); len(left) != 0 {
					nowIPs[clientIP] = left
				}
			}
		}
		if len(nowIPs) != 0 {
			next[key] = installedRule[R]{r, nowIPs}
		}
	}

	return next
}

func needsInstall(refsFor func(dstIP string) []nftElemRef, resolved map[string]bool) bool {
	client := GetNFTClient()
	needs := false
	for dstIP := range resolved {
		refs := refsFor(dstIP)
		if len(refs) == 0 || allElemRefsPresent(refs) {
			continue
		}
		if anyElemRefPresent(refs) {
			deleteElemRefs(client, refs)
		}
		needs = true
	}
	return needs
}

func deleteElements(refsFor func(dstIP string) []nftElemRef, dstIPs map[string]bool) map[string]bool {
	client := GetNFTClient()
	remaining := map[string]bool{}

	for dstIP := range dstIPs {
		refs := refsFor(dstIP)
		if len(refs) == 0 {
			continue
		}

		deleteElemRefs(client, refs)
		if anyElemRefPresent(refs) {
			fmt.Println("[-] PFW failed to delete elements for", dstIP)
			remaining[dstIP] = true
		}
	}

	return remaining
}

var appliedTags = map[string]map[string]bool{}
var appliedGroups = map[string]map[string]bool{}
var siteDNSClients = map[string]string{}

func syncDeviceState(cfg configSnapshot, devices map[string]DeviceEntry) {
	desiredTags := map[string]map[string]bool{}
	desiredGroups := map[string]map[string]bool{}
	for _, rule := range cfg.TagRules {
		if !ruleActive(rule.Disabled, rule.Condition, rule.Time, rule.Expiration) {
			continue
		}
		collectDesiredValues(desiredTags, devices, rule.Client, rule.Tags)
	}
	for _, rule := range cfg.GroupRules {
		if !ruleActive(rule.Disabled, rule.Condition, rule.Time, rule.Expiration) {
			continue
		}
		collectDesiredValues(desiredGroups, devices, rule.Client, rule.Groups)
	}

	for identity, entry := range devices {
		newTags, tagsChanged := mergeValues(entry.DeviceTags, desiredTags[identity], appliedTags[identity])
		newGroups, groupsChanged := mergeValues(entry.Groups, desiredGroups[identity], appliedGroups[identity])
		if tagsChanged || groupsChanged {
			entry.DeviceTags = newTags
			entry.Groups = newGroups
			updateDeviceFunc(identity, entry)
		}
	}

	appliedTags = desiredTags
	appliedGroups = desiredGroups

	syncSiteDNS(cfg, devices)
}

func collectDesiredValues(desired map[string]map[string]bool, devices map[string]DeviceEntry, client ClientIdentifier, values []string) {
	for identity, entry := range devices {
		if !matchClient(client, entry, identity) {
			continue
		}
		set := desired[identity]
		if set == nil {
			set = map[string]bool{}
			desired[identity] = set
		}
		for _, v := range values {
			set[v] = true
		}
	}
}

func mergeValues(current []string, desired, applied map[string]bool) ([]string, bool) {
	out := []string{}
	changed := false
	have := map[string]bool{}
	for _, v := range current {
		if applied[v] && !desired[v] {
			changed = true
			continue
		}
		out = append(out, v)
		have[v] = true
	}
	for v := range desired {
		if !have[v] {
			out = append(out, v)
			changed = true
		}
	}
	return out, changed
}

func syncSiteDNS(cfg configSnapshot, devices map[string]DeviceEntry) {
	type siteCover struct{ iface, dns string }
	desired := map[string]siteCover{}
	for _, fw := range cfg.ForwardingRules {
		if fw.OriginalDst.IP != "0.0.0.0/0" || !strings.HasPrefix(fw.DstInterface, "site") {
			continue
		}
		if !ruleActive(fw.Disabled, fw.Condition, fw.Time, fw.Expiration) {
			continue
		}
		dns := cfg.SiteDNS[fw.DstInterface]
		if dns == "" {
			continue
		}
		for _, ip := range clientIPsFrom(devices, fw.Client) {
			desired[ip] = siteCover{fw.DstInterface, dns}
		}
	}

	for ip, cover := range desired {
		if siteDNSClients[ip] != cover.iface {
			setDeviceCustomDNS(ip, cover.dns)
			siteDNSClients[ip] = cover.iface
		}
	}
	for ip := range siteDNSClients {
		if _, ok := desired[ip]; !ok {
			setDeviceCustomDNS(ip, "0")
			delete(siteDNSClients, ip)
		}
	}
}

type savedInstalledState struct {
	Forwards map[string]installedFwd
	Blocks   map[string]installedBlk
	SiteDNS  map[string]string
	Tags     map[string]map[string]bool
	Groups   map[string]map[string]bool
}

var InstalledStateFile = TEST_PREFIX + "/state/plugins/pfw/installed.json"
var lastInstalledStateSaved []byte

func saveInstalledState() {
	data, err := json.Marshal(savedInstalledState{installedForwards, installedBlocks, siteDNSClients, appliedTags, appliedGroups})
	if err != nil || bytes.Equal(data, lastInstalledStateSaved) {
		return
	}
	if werr := atomicWriteFile(InstalledStateFile, data); werr != nil {
		fmt.Println("failed to write installed state", werr)
		return
	}
	lastInstalledStateSaved = data
}

func loadInstalledState() {
	data, err := ioutil.ReadFile(InstalledStateFile)
	if err != nil {
		return
	}
	state := savedInstalledState{}
	if json.Unmarshal(data, &state) != nil {
		return
	}
	if state.Forwards != nil {
		installedForwards = state.Forwards
	}
	if state.Blocks != nil {
		installedBlocks = state.Blocks
	}
	if state.SiteDNS != nil {
		siteDNSClients = state.SiteDNS
	}
	if state.Tags != nil {
		appliedTags = state.Tags
	}
	if state.Groups != nil {
		appliedGroups = state.Groups
	}
}

func listToSet(l []string) map[string]bool {
	m := map[string]bool{}
	for _, k := range l {
		m[k] = true
	}
	return m
}

func cloneSet(a map[string]bool) map[string]bool {
	m := make(map[string]bool, len(a))
	for k := range a {
		m[k] = true
	}
	return m
}

func unionSets(a, b map[string]bool) map[string]bool {
	m := cloneSet(a)
	for k := range b {
		m[k] = true
	}
	return m
}

func ruleTimer() {
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		for range ticker.C {
			reconcileNow()
		}
	}()
}

var installedForwards = map[string]installedFwd{}
var installedBlocks = map[string]installedBlk{}

func validPortSpec(port string) bool {
	parts := strings.Split(port, "-")
	if len(parts) > 2 {
		return false
	}
	prev := -1
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 65535 {
			return false
		}
		if n < prev {
			return false
		}
		prev = n
	}
	return true
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

func modifyForwardRules(w http.ResponseWriter, r *http.Request, changed *bool) {

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
			dst_idx := fwdDstIfaceToIndexLocked(fwd.DstInterface)
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

				if !validPortSpec(fwd.OriginalDstPort) {
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

			if fwd.DstPort != "" && !validPortSpec(fwd.DstPort) {
				http.Error(w, "Invalid DstPort", 400)
				return
			}

			if fwd.OriginalDstPort != "" && !validPortSpec(fwd.OriginalDstPort) {
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
				flushDNSCacheIfLastLocked(fwd.OriginalDst)
				*changed = true
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
		flushDNSCacheIfLastLocked(old_fwd.OriginalDst)
	} else {
		gFirewallConfig.ForwardingRules = append(gFirewallConfig.ForwardingRules, fwd)
	}
	saveFirewallRulesLocked()
	*changed = true
}

func modifyBlockRules(w http.ResponseWriter, r *http.Request, changed *bool) {

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

		if br.DstPort != "" && !validPortSpec(br.DstPort) {
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
				flushDNSCacheIfLastLocked(br.Dst)
				*changed = true
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	if index_ok {
		old_br := gFirewallConfig.BlockRules[index]
		gFirewallConfig.BlockRules[index] = br
		flushDNSCacheIfLastLocked(old_br.Dst)
	} else {
		gFirewallConfig.BlockRules = append(gFirewallConfig.BlockRules, br)
	}
	saveFirewallRulesLocked()
	*changed = true
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
			err = AddDstSupernetworksAcceptRule("inet", "mangle", "mark"+markidx)
		}
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

func modifyTags(w http.ResponseWriter, r *http.Request, changed *bool) {

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
				*changed = true
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	if index_ok {
		gFirewallConfig.TagRules[index] = rule
	} else {
		gFirewallConfig.TagRules = append(gFirewallConfig.TagRules, rule)
	}
	saveFirewallRulesLocked()
	*changed = true
}

func modifyGroups(w http.ResponseWriter, r *http.Request, changed *bool) {

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
				*changed = true
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	if index_ok {
		gFirewallConfig.GroupRules[index] = rule
	} else {
		gFirewallConfig.GroupRules = append(gFirewallConfig.GroupRules, rule)
	}
	saveFirewallRulesLocked()
	*changed = true
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
	loadInstalledState()
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
	unix_plugin_router.HandleFunc("/block", withConfigMutation(modifyBlockRules)).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/block/{index:[0-9]+}", withConfigMutation(modifyBlockRules)).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/forward", withConfigMutation(modifyForwardRules)).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/forward/{index:[0-9]+}", withConfigMutation(modifyForwardRules)).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/variable/{name}", handleVariable).Methods("DELETE", "GET", "PUT")
	unix_plugin_router.HandleFunc("/testExpression", testExpression).Methods("POST")

	unix_plugin_router.HandleFunc("/tag", withConfigMutation(modifyTags)).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/tag/{index:[0-9]+}", withConfigMutation(modifyTags)).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/group", withConfigMutation(modifyGroups)).Methods("DELETE", "PUT")
	unix_plugin_router.HandleFunc("/group/{index:[0-9]+}", withConfigMutation(modifyGroups)).Methods("DELETE", "PUT")

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
