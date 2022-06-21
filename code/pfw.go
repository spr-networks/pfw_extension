package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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

var TEST_PREFIX = os.Getenv("TEST_PREFIX")
var UNIX_PLUGIN_LISTENER = TEST_PREFIX + "/state/plugins/pfw/socket"
var FirewallConfigFile = TEST_PREFIX + "/configs/pfw/rules.json"

var FWmtx sync.RWMutex

type ClientIdentifier struct {
	Identity string
	Group    string
	SrcIP    string
	Tag 		 string
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
	DstIP    string
	DstPort  string
}

type ForwardingRule struct {
	PFWRule
	Protocol string

	OriginalDstIP   string
	OriginalDstPort string

	DstIP        string
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
}

type FirewallConfig struct {
	ForwardingRules []ForwardingRule
	BlockRules      []BlockRule
	TagRules        []TagRule
	GroupRules      []GroupRule
	Variables       map[string]interface{}
	SiteVPNs        []SiteVPN
	APIToken        string
}

var gFirewallConfig = FirewallConfig{[]ForwardingRule{}, []BlockRule{}, []TagRule{}, []GroupRule{}, map[string]interface{}{}, []SiteVPN{}, ""}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func getPFWConfig(w http.ResponseWriter, r *http.Request) {
	loadFirewallRules()

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
	FWmtx.RLock()
	defer FWmtx.RUnlock()
	data, err := ioutil.ReadFile(FirewallConfigFile)
	if err != nil {
		return err
	} else {
		err := json.Unmarshal(data, &gFirewallConfig)
		if err != nil {
			return err
		}
	}
	return nil
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

type DeviceEntry struct {
	Name       string
	MAC        string
	WGPubKey   string
	VLANTag    string
	RecentIP   string
	PSKEntry   PSKEntry
	Groups     []string
	DeviceTags []string
}

type PSKEntry struct {
	Type string
	Psk  string
}

func fetchAPIDevices() map[string]DeviceEntry {
	devs := map[string]DeviceEntry{}

	cli := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, "http://localhost:80/devices", nil)
	if err != nil {
		fmt.Println(err)
		return devs
	}

	FWmtx.RLock()
	token := gFirewallConfig.APIToken
	FWmtx.RUnlock()

	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := cli.Do(req)
	if err != nil {
		fmt.Println("request failed", err)
		return devs
	}

	defer resp.Body.Close()

	json.NewDecoder(resp.Body).Decode(&devs)

	return devs
}

func updateDevice(identity string, entry DeviceEntry) {
	//Ensure PSKEntry is not modified
	entry.PSKEntry.Psk = ""
	entry.PSKEntry.Type = ""

	cli := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

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

var gDevices = make(map[string]DeviceEntry)

func APIDevices() map[string]DeviceEntry {
	return gDevices
}

func updateAPIData() {
	gDevices = fetchAPIDevices()
}

func clientIPs(client ClientIdentifier) []string {
	//return a list of IPs from a ClientIdentifier
	if client.SrcIP != "" {
		return []string{client.SrcIP}
	}

	devices := APIDevices()

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

func isBlockInstalled(br BlockRule, clientIP string) bool {
	cmd := exec.Command("nft", "get", "element", "inet", "filter", blockVmapName, "{",
		clientIP, ".", br.DstIP, ".", br.Protocol, ".", br.DstPort, ":", blockVerdict, "}")

	err := cmd.Run()

	if err != nil {
		return false
	} else {
		return true
	}
}

func addBlock(br BlockRule, clientIP string) error {
	cmd := exec.Command("nft", "add", "element", "inet", "filter", blockVmapName, "{",
		clientIP, ".", br.DstIP, ".", br.Protocol, ".", br.DstPort, ":", blockVerdict, "}")

	_, err := cmd.Output()

	if err != nil {
		fmt.Println("failed to add element", err)
		fmt.Println(cmd)
	}
	return err
}

func deleteBlock(br BlockRule, clientIP string) error {
	cmd := exec.Command("nft", "delete", "element", "inet", "filter", blockVmapName, "{",
		clientIP, ".", br.DstIP, ".", br.Protocol, ".", br.DstPort, ":", blockVerdict, "}")

	_, err := cmd.Output()

	if err != nil {
		fmt.Println("failed to delete element", err)
		fmt.Println(cmd)
	}

	return err
}

func isForwardingInstalled(fwd ForwardingRule, clientIP string) bool {
	var cmd *exec.Cmd

	if fwd.DstInterface != "" {
		//if a destination interface is set, only check clientIP and OriginalDstIP
		cmd = exec.Command("nft", "get", "element", "inet", "mangle", "site_forward_mangle", "{",
			clientIP, ".", fwd.OriginalDstIP, ":", "jump mark" + fwdDstIfaceToIndex(fwd.DstInterface), "}")
	} else {
		if fwd.OriginalDstPort != "" {
			cmd = exec.Command("nft", "get", "element", "inet", "nat", "dnat_"+fwd.Protocol+"_ipmap", "{",
				clientIP, ".", fwd.OriginalDstIP, ".", fwd.OriginalDstPort, ":", fwd.DstIP, "}")

		} else {
			cmd = exec.Command("nft", "get", "element", "inet", "nat", "dnat_"+fwd.Protocol+"_anymap", "{",
				clientIP, ".", fwd.OriginalDstIP, ".", fwd.OriginalDstPort, ":", fwd.DstIP, "}")
		}
	}


	err := cmd.Run()

	if err != nil {
		return false
	} else {
		return true
	}
}


var SiteMarkOffset = 1000

func fwdDstIfaceToIndex(iface string) string {
	if !strings.HasPrefix(iface, "site") {
		return ""
	}

	val, err := strconv.Atoi(iface[4:])
	if err != nil {
		return ""
	}

	return strconv.Itoa(val + SiteMarkOffset)
}

func addForwarding(fwd ForwardingRule, clientIP string) error {
	var cmd *exec.Cmd

	if fwd.DstInterface != "" {
		//if a destination interface is set, only check clientIP and OriginalDstIP
		cmd = exec.Command("nft", "add", "element", "inet", "mangle", "site_forward_mangle", "{",
			clientIP, ".", fwd.OriginalDstIP, ":", "jump mark" + fwdDstIfaceToIndex(fwd.DstInterface), "}")
	} else {

		if fwd.OriginalDstPort != "" {
			cmd = exec.Command("nft", "add", "element", "inet", "nat", "dnat_"+fwd.Protocol+"_ipmap", "{",
				clientIP, ".", fwd.OriginalDstIP, ".", fwd.OriginalDstPort, ":", fwd.DstIP, "}")

			err := cmd.Run()
			if err != nil {
				fmt.Println("failed to add element", err)
				fmt.Println(cmd)
				return err
			}

			cmd = exec.Command("nft", "add", "element", "inet", "nat", "dnat_"+fwd.Protocol+"_portmap", "{",
				clientIP, ".", fwd.OriginalDstIP, ".", fwd.OriginalDstPort, ":", fwd.DstPort, "}")

		} else {
			cmd = exec.Command("nft", "add", "element", "inet", "nat", "dnat_"+fwd.Protocol+"_anymap", "{",
				clientIP, ".", fwd.OriginalDstIP, ".", fwd.OriginalDstPort, ":", fwd.DstIP, "}")
		}
	}

	err := cmd.Run()
	if err != nil {
		fmt.Println("failed to add element", err)
		fmt.Println(cmd)
	}

	return err
}

func deleteForwarding(fwd ForwardingRule, clientIP string) error {
	var cmd *exec.Cmd

	if fwd.DstInterface != "" {
		//if a destination interface is set, only check clientIP and OriginalDstIP
		cmd = exec.Command("nft", "delete", "element", "inet", "mangle", "site_forward_mangle", "{",
			clientIP, ".", fwd.OriginalDstIP, ":", "jump mark" + fwdDstIfaceToIndex(fwd.DstInterface), "}")
	} else {

		if fwd.OriginalDstPort != "" {
			cmd = exec.Command("nft", "delete", "element", "inet", "nat", "dnat_"+fwd.Protocol+"_ipmap", "{",
				clientIP, ".", fwd.OriginalDstIP, ".", fwd.OriginalDstPort, ":", fwd.DstIP, "}")

			err := cmd.Run()
			if err != nil {
				fmt.Println("failed to delete element", err)
				fmt.Println(cmd)
			}

			cmd = exec.Command("nft", "delete", "element", "inet", "nat", "dnat_"+fwd.Protocol+"_portmap", "{",
				clientIP, ".", fwd.OriginalDstIP, ".", fwd.OriginalDstPort, ":", fwd.DstPort, "}")

		} else {
			cmd = exec.Command("nft", "delete", "element", "inet", "nat", "dnat_"+fwd.Protocol+"_anymap", "{",
				clientIP, ".", fwd.OriginalDstIP, ".", fwd.OriginalDstPort, ":", fwd.DstIP, "}")
		}
	}

	err := cmd.Run()
	if err != nil {
		fmt.Println("failed to delete element", err)
		fmt.Println(cmd)
	}

	return err
}

//https://stackoverflow.com/questions/55093676/checking-if-current-time-is-in-a-given-interval-golang
func inTimeSpan(start, end, check time.Time) bool {
	if start.Before(end) {
		return !check.Before(start) && !check.After(end)
	}
	if start.Equal(end) {
		return check.Equal(start)
	}
	return !start.After(check) || !end.Before(check)
}

//returns true if the current time is matched
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
	return value.(bool), nil
}

func ruleActive(disabled bool, condition string, t TimeExpression) bool {
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
	for _, fw := range gFirewallConfig.ForwardingRules {
		for _, clientIP := range clientIPs(fw.Client) {
			if ruleExpired(fw.Expiration) {
				continue
			}

			is_installed := isForwardingInstalled(fw, clientIP)
			if ruleActive(fw.Disabled, fw.Condition, fw.Time) {
				if !is_installed {
					addForwarding(fw, clientIP)
				}
			} else if is_installed {
				deleteForwarding(fw, clientIP)
			}

		}
	}

	//block rules
	for _, br := range gFirewallConfig.BlockRules {
		for _, clientIP := range clientIPs(br.Client) {
			if ruleExpired(br.Expiration) {
				continue
			}

			is_installed := isBlockInstalled(br, clientIP)
			if ruleActive(br.Disabled, br.Condition, br.Time) {
				if !is_installed {
					addBlock(br, clientIP)
				}
			} else if is_installed {
				deleteBlock(br, clientIP)
			}

		}
	}

	//tag assignment rules
	for _, rule := range gFirewallConfig.TagRules {
		if ruleExpired(rule.Expiration) {
			continue
		}
		if ruleActive(rule.Disabled, rule.Condition, rule.Time) {
			addClient("tag", rule.Client, rule.Tags)
		} else {
			removeClient("tag", rule.Client, rule.Tags)
		}
	}

	//group assignment rules
	for _, rule := range gFirewallConfig.GroupRules {
		if ruleExpired(rule.Expiration) {
			continue
		}

		if ruleActive(rule.Disabled, rule.Condition, rule.Time) {
			addClient("group", rule.Client, rule.Groups)
		} else {
			removeClient("group", rule.Client, rule.Groups)
		}
	}

}

func initUserFirewallRules() {
	loadFirewallRules()

	FWmtx.RLock()
	defer FWmtx.RUnlock()

	applyFirewallRulesLocked()
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
		if index < 0 || index >= len(gFirewallConfig.BlockRules) {
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

		//for now only support interfaces named siteX
		if fwd.DstInterface != "" {
			if !strings.HasPrefix(fwd.DstInterface, "site") {
				http.Error(w, "Forwarding Interfaces must start with site[0-9]+ "+err.Error(), 400)
				return
			}

			dst_idx := fwdDstIfaceToIndex(fwd.DstInterface)
			if dst_idx == "" {
				http.Error(w, "Forwarding Interfaces must start with site[0-9]+ "+err.Error(), 400)
				return
			}

			if fwd.DstPort != "" || fwd.OriginalDstPort != "" {
				http.Error(w, "When a DstInterface is set, DstPort is not supported", 400)
				return
			}

			if fwd.DstIP != "" {
				http.Error(w, "When a DstInterface is set, DstIP rewriting is not supported", 400)
				return
			}
		} else {
			//ports and new DstIp only needed if there is no DstInterface

			if fwd.Protocol != "tcp" && fwd.Protocol != "udp" {
				http.Error(w, "Invalid protocol", 400)
				return
			}

			re := regexp.MustCompile("^([0-9].*-[0-9].*|[0-9]*)$")

			if fwd.DstPort != "" && !re.MatchString(fwd.DstPort) {
				if err != nil {
					http.Error(w, "Invalid DstPort", 400)
					return
				}
			}

			if fwd.OriginalDstPort != "" && !re.MatchString(fwd.OriginalDstPort) {
				if err != nil {
					http.Error(w, "Invalid OriginalDstPort", 400)
					return
				}
			}

			ip := net.ParseIP(fwd.DstIP)
			if ip == nil {
				http.Error(w, "Invalid DstIP", 400)
				return
			}

		}


		err = validateClientIdentifier(fwd.Client)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		err = CIDRorIP(fwd.OriginalDstIP)
		if err != nil {
			http.Error(w, "Invalid OriginalDstIP "+err.Error(), 400)
			return
		}
	}

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.ForwardingRules {
			a := gFirewallConfig.ForwardingRules[i]
			if fwd == a {
				gFirewallConfig.ForwardingRules = append(gFirewallConfig.ForwardingRules[:i], gFirewallConfig.ForwardingRules[i+1:]...)
				saveFirewallRulesLocked()

				FWmtx.Unlock()
				for _, clientIP := range clientIPs(fwd.Client) {
					deleteForwarding(fwd, clientIP)
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
		FWmtx.Unlock()
		for _, clientIP := range clientIPs(old_fwd.Client) {
			deleteForwarding(old_fwd, clientIP)
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

		if CIDRorIP(br.DstIP) != nil {
			http.Error(w, "Invalid DstIP", 400)
			return
		}
	}

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.BlockRules {
			a := gFirewallConfig.BlockRules[i]
			if br == a {
				gFirewallConfig.BlockRules = append(gFirewallConfig.BlockRules[:i], gFirewallConfig.BlockRules[i+1:]...)
				saveFirewallRulesLocked()

				FWmtx.Unlock()
				//delete the block rules for the clients where it applies
				for _, clientIP := range clientIPs(br.Client) {
					deleteBlock(br, clientIP)
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

		FWmtx.Unlock()
		for _, clientIP := range clientIPs(old_br.Client) {
			deleteBlock(old_br, clientIP)
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
				http.Error(w, "Could not derive PublicKey from PrivateKey: " + err.Error(), 400)
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
	err = exec.Command("nft", "list", "chain", "inet", "mangle", "mark"+strconv.Itoa(idx + SiteMarkOffset)).Run()
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

func createSiteVPN(i int, vpn SiteVPN) {
	markidx := strconv.Itoa(SiteMarkOffset + i)
	idx := strconv.Itoa(i)

	err := saveSiteConfig(i, vpn)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = exec.Command("ip", "link", "add", "site"+idx, "type", "wireguard").Run()
	if err != nil {
		fmt.Println("ip link add site" + idx + " failed")
		fmt.Println(err)
		return
	}

	err = exec.Command("wg", "setconf", "site"+idx, siteConfigPath(i)).Run()
	if err != nil {
		fmt.Println("wg setconf site" + idx + " failed")
		fmt.Println(err)
		return
	}

	err = exec.Command("ip", "addr", "add", vpn.Address, "dev", "site"+idx).Run()
	if err != nil {
		fmt.Println("ip addr add " + vpn.Address + " dev site" + idx + " failed")
		fmt.Println(err)
		return
	}

	err = exec.Command("ip", "link", "set", "site"+idx, "up").Run()
	if err != nil {
		fmt.Println("ip link set site" + idx + " up failed")
		fmt.Println(err)
		return
	}

	//check nft chain and create it if it does not exist
	err = exec.Command("nft", "list", "chain", "inet", "mangle", "mark"+markidx).Run()
	if err != nil {
		//create it
		err = exec.Command("nft", "add", "chain", "inet", "mangle", "mark"+markidx).Run()
		if err != nil {
			fmt.Println("nft add chain " + markidx + " failed")
			fmt.Println(err)
			return
		}

		err = exec.Command("nft", "add", "rule", "inet", "mangle", "mark"+markidx,
			"meta", "mark", "set", markidx).Run()
		if err != nil {
			//delete the chain
			err = exec.Command("nft", "delete", "chain", "inet", "mangle", "mark"+markidx).Run()
			fmt.Println("failed to add rule for mark" + markidx)
			fmt.Println(err)
			return
		}
	}

	//add policy-based routes
	err = exec.Command("ip", "-4", "route", "add", "0.0.0.0/0", "dev", "site"+idx, "table", markidx).Run()
	if err != nil {
		fmt.Println("failed to add site" + idx + " table")
		fmt.Println(err)
		return
	}

	err = exec.Command("ip", "-4", "rule", "add", "from", "all", "fwmark", markidx, "table", markidx).Run()
	if err != nil {
		fmt.Println("failed to add site" + idx + " fwmark rule")
		fmt.Println(err)
		return
	}

}

func applySiteVPNs() {
	for i, siteVPN := range gFirewallConfig.SiteVPNs {
		//check if siteVPN is online and happy. if not, remake it
		currentSite, err := checkSiteVPNIndex(i)
		if err == nil && currentSite == siteVPN {
			//configuration matches, all done for this one
			continue
		} else {
			//destroy the interface and re-create it
			exec.Command("ip", "link", "del", "site"+strconv.Itoa(i)).Run()
			createSiteVPN(i, siteVPN)
		}
	}

}

/*

tbd verdict maps  for site forward

// src ip . dst_ip --> verdict is goto mark1000 to f.ex. go to site inetrace with mark/table 1000

map site_dest {
	type ipv4_addr . ipv4_addr : verdict;
	flags interval
}

//tbd:
need to update ForwardingRule to apply when DstInterface is set.


*/

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
				FWmtx.RLock()
				applyFirewallRulesLocked()
				FWmtx.RUnlock()
			}
		}
	}

	go runTimer()
}

func refreshDataTimer() {

	updateAPIData()

	tick := time.NewTicker(1 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			updateAPIData()
		}
	}
}

func matchClient(client ClientIdentifier, entry DeviceEntry, identity string) bool {
	if client.Identity != "" && identity == client.Identity {
		return true
	}

	if client.SrcIP != "" && entry.RecentIP == client.SrcIP {
		return true
	}

	//check groups
	for _, group := range entry.Groups {
		if group == client.Group {
			return true
		}
	}

	return false
}

func removeClient(property string, client ClientIdentifier, values []string) {

	devices := APIDevices()

	for identity, entry := range devices {
		if matchClient(client, entry, identity) {
			newGroups := []string{}

			entry_vals := entry.Groups
			if property == "tag" {
				entry_vals = entry.DeviceTags
			}

			for _, cur_group := range entry_vals {
				skipGroup := false
				for _, val_group := range values {
					if cur_group == val_group {
						skipGroup = true
						break
					}
				}

				if !skipGroup {
					newGroups = append(newGroups, cur_group)
				}

				if len(newGroups) != len(entry_vals) {
					//change groups or tags for this entry
					if property == "group" {
						entry.Groups = newGroups
					} else {
						entry.DeviceTags = newGroups
					}
					updateDevice(identity, entry)
				}
			}

		}
	}

}

func addClient(property string, client ClientIdentifier, values []string) {

	devices := APIDevices()

	for identity, entry := range devices {
		if matchClient(client, entry, identity) {

			entry_vals := entry.Groups
			if property == "tag" {
				entry_vals = entry.DeviceTags
			}

			newGroups := entry_vals

			for _, val_group := range values {
				skipGroup := false
				for _, cur_group := range entry_vals {
					if cur_group == val_group {
						skipGroup = true
						break
					}
				}

				if !skipGroup {
					newGroups = append(newGroups, val_group)
				}

				if len(newGroups) != len(entry_vals) {
					//change groups or tags for this entry
					if property == "group" {
						entry.Groups = newGroups
					} else {
						entry.DeviceTags = newGroups
					}
					updateDevice(identity, entry)
				}
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

func initPFW() {
	loadFirewallRules()
	applySiteVPNs()
	go refreshDataTimer()
	ruleTimer()
}

func main() {
	unix_plugin_router := mux.NewRouter().StrictSlash(true)

	unix_plugin_router.HandleFunc("/config", getPFWConfig).Methods("GET")
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

	os.Remove(UNIX_PLUGIN_LISTENER)
	unixPluginListener, err := net.Listen("unix", UNIX_PLUGIN_LISTENER)
	if err != nil {
		panic(err)
	}

	pluginServer := http.Server{Handler: logRequest(unix_plugin_router)}

	initPFW()

	pluginServer.Serve(unixPluginListener)
}
