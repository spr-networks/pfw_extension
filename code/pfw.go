package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
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

	Protocol string
	DstIP    string
	DstPort  string
}

type BlockRule struct {
	PFWRule
}

type ForwardingRule struct {
	PFWRule
	NewInterface string
	NewDstIP     string
}

type FirewallConfig struct {
	ForwardingRules []ForwardingRule
	BlockRules      []BlockRule
	Variables       map[string]interface{}
}

var gFirewallConfig = FirewallConfig{[]ForwardingRule{}, []BlockRule{}, map[string]interface{}{}}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func getPFWConfig(w http.ResponseWriter, r *http.Request) {
	loadFirewallRules()

	x := gFirewallConfig

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

var DevicesConfigPath = TEST_PREFIX + "/configs/devices/"
var DevicesPublicConfigFile = DevicesConfigPath + "devices-public.json"

func APIDevices() map[string]DeviceEntry {
	devs := map[string]DeviceEntry{}

	data, err := ioutil.ReadFile(DevicesPublicConfigFile)
	if err == nil {
		public_devices := map[string]DeviceEntry{}
		err = json.Unmarshal(data, &public_devices)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		fmt.Println(err)
	}

	return devs
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

func isForwardingInstalled(fw ForwardingRule, clientIP string) bool {
	return false
}

func deleteForwarding(f ForwardingRule, clientIP string) error {
	//not impl yet
	return nil
}

func addForwarding(f ForwardingRule, clientIP string) error {
	//not impl yet
	return nil
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

func ruleActive(condition string, t TimeExpression) bool {

	//if a time is specified and its not active at the current time
	// then the rule is not active
	if timeSet(t) && !activeTime(t) {
		return false
	}

	//check condition variables
	if condition != "" {
		value, err := gval.Evaluate(condition, gFirewallConfig.Variables)
		if err != nil {
			fmt.Println("invalid rule", err)
			return false
		}
		if value == false {
			return false
		}
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

			is_installed := isForwardingInstalled(fw, clientIP)
			if !ruleExpired(fw.Expiration) && ruleActive(fw.Condition, fw.Time) {
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
			is_installed := isBlockInstalled(br, clientIP)
			if !ruleExpired(br.Expiration) && ruleActive(br.Condition, br.Time) {
				if !is_installed {
					addBlock(br, clientIP)
				}
			} else if is_installed {
				deleteBlock(br, clientIP)
			}

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

		if fwd.Protocol != "tcp" && fwd.Protocol != "udp" {
			http.Error(w, "Invalid protocol", 400)
			return
		}

		re := regexp.MustCompile("^([0-9].*-[0-9].*|[0-9]*)$")

		if !re.MatchString(fwd.DstPort) {
			if err != nil {
				http.Error(w, "Invalid DstPort", 400)
				return
			}
		}

		if fwd.DstPort == "" {
			//all ports
			fwd.DstPort = "0-65535"
		}

		err = validateClientIdentifier(fwd.Client)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		ip := net.ParseIP(fwd.DstIP)
		if ip == nil {
			http.Error(w, "Invalid DstIP", 400)
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
	value, err := gval.Evaluate(string(body), gFirewallConfig.Variables)

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

func initPFW() {

	/*
			inet filter

		  map fwd_block {
		    type ipv4_addr . ipv4_addr . inet_proto . inet_service : verdict;
		    flags interval
		  }

			chain PFWDROPLOG {
				counter log prefix "DRP:PFW "
				counter drop
			}

			-> after clamping we want these rules. we could add a jump to PFW chain
			# MSS clamping to handle upstream MTU limitations
			tcp flags syn tcp option maxseg size set rt mtu

			mb jump
			counter ip saddr . ip daddr . ip protocol . tcp dport vmap @fwd_block
			counter ip saddr . ip daddr . ip protocol . udp dport vmap @fwd_block

			//goto PFWDROPLOG
	*/

	loadFirewallRules()
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

	os.Remove(UNIX_PLUGIN_LISTENER)
	unixPluginListener, err := net.Listen("unix", UNIX_PLUGIN_LISTENER)
	if err != nil {
		panic(err)
	}

	pluginServer := http.Server{Handler: logRequest(unix_plugin_router)}

	initPFW()

	pluginServer.Serve(unixPluginListener)
}
