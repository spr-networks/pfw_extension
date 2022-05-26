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
	"github.com/gorilla/mux"
	"github.com/PaesslerAG/gval"
)

var TEST_PREFIX = os.Getenv("TEST_PREFIX")
var UNIX_PLUGIN_LISTENER = TEST_PREFIX + "/state/plugins/pfw/socket"

var FWmtx sync.Mutex

type BlockRule struct {
	SrcIP     string
	DstIP     string
	SrcPort		string
	Protocol  string
	CronExpr  string
	Condition string
	Duration  string
}

type ForwardingRule struct {
	SrcIP     string
	DstIP     string
	SrcPort		string
	Protocol  string
	CronExpr  string
	Condition string
	Duration  string

	NewDstIP	string
	DstPort		string
}

type FirewallConfig struct {
	ForwardingRules []ForwardingRule
	BlockRules      []BlockRule
	Variables				map[string]interface{}
}

var FirewallConfigFile = TEST_PREFIX + "/configs/pfw/rules.json"
var gFirewallConfig = FirewallConfig{[]ForwardingRule{}, []BlockRule{}, map[string]interface{}{} }

func pluginTest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", 400)
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}


func getPFWConfig(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()
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
	FWmtx.Lock()
	defer FWmtx.Unlock()
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

func deleteBlock(br BlockRule) error {
	cmd := exec.Command("nft", "add", "element", "inet", "nat", "block", "{",
		br.SrcIP, ".", br.DstIP, ".", br.Protocol, ":", "drop", "}")

	_, err := cmd.Output()

	if err != nil {
		fmt.Println("failed to delete element", err)
		fmt.Println(cmd)
	}

	return err
}

func deleteForwarding(f ForwardingRule) error {
	var cmd *exec.Cmd
	if f.SrcPort == "any" {
		cmd = exec.Command("nft", "delete", "element", "inet", "nat", f.Protocol+"anyfwd",
			"{", f.SrcIP, ":",
			f.DstIP, "}")

	} else {
		cmd = exec.Command("nft", "delete", "element", "inet", "nat", f.Protocol+"fwd",
			"{", f.SrcIP, ".", f.SrcPort, ":",
			f.DstIP, ".", f.DstPort, "}")
	}
	_, err := cmd.Output()

	if err != nil {
		fmt.Println("failed to delete element", err)
		fmt.Println(cmd)
	}

	return err

}

func applyForwarding(forwarding []ForwardingRule) error {

	//need to flush the fwd rules here ?

	for _, f := range forwarding {
		var cmd *exec.Cmd
		if f.SrcPort == "any" {
			cmd = exec.Command("nft", "add", "element", "inet", "nat", f.Protocol+"anyfwd",
				"{", f.SrcIP, ":",
				f.DstIP, "}")

		} else {
			cmd = exec.Command("nft", "add", "element", "inet", "nat", f.Protocol+"fwd",
				"{", f.SrcIP, ".", f.SrcPort, ":",
				f.DstIP, ".", f.DstPort, "}")
		}
		_, err := cmd.Output()

		if err != nil {
			fmt.Println("failed to add element", err)
			fmt.Println(cmd)
		}

	}

	return nil
}

func applyBlocking(blockRules []BlockRule) error {
	for _, br := range blockRules {
		cmd := exec.Command("nft", "add", "element", "inet", "nat", "block", "{",
			br.SrcIP, ".", br.DstIP, ".", br.Protocol, ":", "drop", "}")

		_, err := cmd.Output()

		if err != nil {
			fmt.Println("failed to add element", err)
			fmt.Println(cmd)
		}
	}

	return nil
}

func applyFirewallRulesLocked() {

	applyForwarding(gFirewallConfig.ForwardingRules)

	applyBlocking(gFirewallConfig.BlockRules)
}

func initUserFirewallRules() {
	loadFirewallRules()

	FWmtx.Lock()
	defer FWmtx.Unlock()

	applyFirewallRulesLocked()

	x := func() {
		//TBD expose upstream_tcp_port_drop nfmap to UI for toggling
		enable_upstream := os.Getenv("UPSTREAM_SERVICES_ENABLE")
		if enable_upstream != "" {
			cmd := exec.Command("nft", "flush", "map", "inet", "filter", "upstream_tcp_port_drop")
			_, err := cmd.Output()

			if err != nil {
				fmt.Println("Failed to disable", err)
				fmt.Println(cmd)
			}
		}
	}

	// Workaround for docker-compose, which may start api very shortly
	// after base is started, but before the rules are loaded.

	//run immediately
	x()

	//and also in 10 seconds
	go func() {
		time.Sleep(10 * time.Second)
		x()
	}()

}

func getFirewallConfig(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gFirewallConfig)
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

	re := regexp.MustCompile("^[0-9\\-]*$")

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

	if CIDRorIP(fwd.SrcIP) != nil {
		http.Error(w, "Invalid SrcIP", 400)
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
				deleteForwarding(a)
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	gFirewallConfig.ForwardingRules = append(gFirewallConfig.ForwardingRules, fwd)
	saveFirewallRulesLocked()
	applyFirewallRulesLocked()
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
		http.Error(w, err.Error(), 400)
		return
	}

	if CIDRorIP(br.SrcIP) != nil {
		http.Error(w, "Invalid SrcIP", 400)
		return
	}

	if CIDRorIP(br.SrcIP) != nil {
		http.Error(w, "Invalid DstIP", 400)
		return
	}

	if r.Method == http.MethodDelete {
		for i := range gFirewallConfig.BlockRules {
			a := gFirewallConfig.BlockRules[i]
			if br == a {
				gFirewallConfig.BlockRules = append(gFirewallConfig.BlockRules[:i], gFirewallConfig.BlockRules[i+1:]...)
				saveFirewallRulesLocked()
				deleteBlock(a)
				return
			}
		}
		http.Error(w, "Not found", 404)
		return
	}

	gFirewallConfig.BlockRules = append(gFirewallConfig.BlockRules, br)
	saveFirewallRulesLocked()
	applyFirewallRulesLocked()
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
			http.Error(w, "Invalid type: " + vType + ". Only strings and numbers are supported", 400)
			return
		}

		gFirewallConfig.Variables[name] = value
		saveFirewallRulesLocked()
	}
}

func testExpression(w http.ResponseWriter, r *http.Request) {
	FWmtx.Lock()
	defer FWmtx.Unlock()

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

func main() {

	loadFirewallRules()

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

	pluginServer.Serve(unixPluginListener)
}
