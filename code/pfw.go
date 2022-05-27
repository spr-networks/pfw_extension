package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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

var FWmtx sync.RWMutex

type ClientIdentifier struct {
	Identity  string
	Group     string
	SrcIP     string
}

type BlockRule struct {
	Client 		ClientIdentifier
	DstIP     string
	DstPort   string
	Protocol  string
	CronExpr  string
	Condition string
}

type ForwardingRule struct {
	Client		ClientIdentifier
	DstIP     string
	SrcPort   string
	Protocol  string
	CronExpr  string
	Condition string

	NewDstIP string
	DstPort  string
}

type FirewallConfig struct {
	ForwardingRules []ForwardingRule
	BlockRules      []BlockRule
	Variables       map[string]interface{}
}

var FirewallConfigFile = TEST_PREFIX + "/configs/pfw/rules.json"
var gFirewallConfig = FirewallConfig{[]ForwardingRule{}, []BlockRule{}, map[string]interface{}{}}


func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}

func getPFWConfig(w http.ResponseWriter, r *http.Request) {
	FWmtx.RLock()
	defer FWmtx.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gFirewallConfig)
}

func saveFirewallRulesLocked() {
	file, _ := json.MarshalIndent(gFirewallConfig, "", " ")
	err := ioutil.WriteFile(FirewallConfigFile, file, 0600)
	if err != nil {
		log.Fatal(err)
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

func clientIPs(client ClientIdentifier) []string {
	//return a list of IPs from a ClientIdentifier
	if client.SrcIP != "" {
		return []string{client.SrcIP}
	}

	if client.Identity != "" {
		//look up last recent ip for the rule
	}

	if client.Group != "" {
		//ips := []string{}
		//for each device in the group, get the recent ip and return those
	}

	return []string{}
}

func isBlockInstalled(br BlockRule, clientIP string) bool {
	cmd := exec.Command("nft", "get", "element", "inet", "nat", blockVmapName, "{",
		clientIP, ".", br.DstIP, ".", br.Protocol, ".", br.DstPort, ":", blockVerdict, "}")

	err := cmd.Run()

	if err != nil {
		return false
	} else {
		return true
	}
}

func addBlock(br BlockRule, clientIP string) error {
	cmd := exec.Command("nft", "add", "element", "inet", "nat", blockVmapName, "{",
		clientIP, ".", br.DstIP, ".", br.Protocol, ".", br.DstPort, ":", blockVerdict, "}")

	_, err := cmd.Output()

	if err != nil {
		fmt.Println("failed to add element", err)
		fmt.Println(cmd)
	}
	return err
}

func deleteBlock(br BlockRule, clientIP string) error {
	cmd := exec.Command("nft", "delete", "element", "inet", "nat", blockVmapName, "{",
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

func ruleActive(condition string, cron string) bool {
	cronChecker := cronexpr.New()

	//check if time is active
	if cron != "" {
		if !cronChecker.IsValid(cron) {
			fmt.Println("Invalid cron expression", cron)
			return false
		}

		val, err := cronChecker.IsDue(cron)
		if err != nil {
			fmt.Println("Invalid cron expression", err.Error())
			return false
		}

		if val == false {
			return false
		}
	}

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

func applyFirewallRulesLocked() {

	//forwarding rules
	for _, fw := range gFirewallConfig.ForwardingRules {
		for _, clientIP := range(clientIPs(fw.Client)) {

			is_installed := isForwardingInstalled(fw, clientIP)
			if ruleActive(fw.Condition, fw.CronExpr) && !is_installed {
				addForwarding(fw, clientIP)
			} else if is_installed {
				deleteForwarding(fw, clientIP)
			}

		}
	}

	//block rules
	for _, br := range gFirewallConfig.BlockRules {
		for _, clientIP := range(clientIPs(br.Client)) {
			is_installed := isBlockInstalled(br, clientIP)
			if ruleActive(br.Condition, br.CronExpr) && !is_installed {
				addBlock(br, clientIP)
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

	fwd := ForwardingRule{}
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

	if fwd.SrcPort != "any" && !re.MatchString(fwd.SrcPort) {
		http.Error(w, "Invalid SrcPort", 400)
		return
	}

	if fwd.DstPort != "any" {
		_, err = strconv.Atoi(fwd.DstPort)
		if err != nil {
			http.Error(w, "Invalid DstPort", 400)
			return
		}
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

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.ForwardingRules {
			a := gFirewallConfig.ForwardingRules[i]
			if fwd == a {
				gFirewallConfig.ForwardingRules = append(gFirewallConfig.ForwardingRules[:i], gFirewallConfig.ForwardingRules[i+1:]...)
				saveFirewallRulesLocked()
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	gFirewallConfig.ForwardingRules = append(gFirewallConfig.ForwardingRules, fwd)
	saveFirewallRulesLocked()
}

func modifyBlockRules(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()

	br := BlockRule{}
	err := json.NewDecoder(r.Body).Decode(&br)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if br.Protocol != "tcp" && br.Protocol != "udp" {
		http.Error(w, "invalid protocol", 400)
		return
	}

	//this would accept -1 etc, which is invalid
	re := regexp.MustCompile("^([0-9].*-[0-9].*|[0-9]*)$")

	if !re.MatchString(br.DstPort) {
		http.Error(w, "Invalid SrcPort", 400)
		return
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

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.BlockRules {
			a := gFirewallConfig.BlockRules[i]
			if br == a {
				gFirewallConfig.BlockRules = append(gFirewallConfig.BlockRules[:i], gFirewallConfig.BlockRules[i+1:]...)
				saveFirewallRulesLocked()
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	gFirewallConfig.BlockRules = append(gFirewallConfig.BlockRules, br)
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
	unix_plugin_router.HandleFunc("/forward", modifyForwardRules).Methods("DELETE", "PUT")
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
