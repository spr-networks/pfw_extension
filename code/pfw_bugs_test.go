package main

// Regression tests for fixed bugs.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
)

// checkCondition must error, not panic, when a condition is not a boolean
func TestCheckConditionNonBool(t *testing.T) {
	_, err := checkCondition("1+1")
	if err == nil {
		t.Error("checkCondition(\"1+1\") = nil error, want error")
	}

	val, err := checkCondition("1 == 1")
	if err != nil {
		t.Fatalf("checkCondition(\"1 == 1\") error = %v", err)
	}
	if !val {
		t.Error("checkCondition(\"1 == 1\") = false, want true")
	}
}

// Tag-based ClientIdentifiers must match devices by DeviceTags
func TestMatchClientTag(t *testing.T) {
	entry := DeviceEntry{
		RecentIP:   "192.168.2.50",
		Groups:     []string{"lan"},
		DeviceTags: []string{"iot", "camera"},
	}

	if !matchClient(ClientIdentifier{Tag: "iot"}, entry, "dev1") {
		t.Error("Tag selector did not match a device carrying the tag")
	}
	if matchClient(ClientIdentifier{Tag: "printer"}, entry, "dev1") {
		t.Error("Tag selector matched a device without the tag")
	}
	if !matchClient(ClientIdentifier{Group: "lan"}, entry, "dev1") {
		t.Error("Group selector did not match")
	}
	if matchClient(ClientIdentifier{Identity: "other"}, entry, "dev1") {
		t.Error("empty Group/Tag selector matched unrelated device")
	}
}

func saveConfigGlobals(t *testing.T) {
	t.Helper()
	oldFile := FirewallConfigFile
	oldConfig := gFirewallConfig
	t.Cleanup(func() {
		FirewallConfigFile = oldFile
		gFirewallConfig = oldConfig
	})
}

// the IP->Address migration must not drop user variables
func TestMigrationPreservesVariables(t *testing.T) {
	saveConfigGlobals(t)

	dir := t.TempDir()
	FirewallConfigFile = filepath.Join(dir, "rules.json")

	old := OldFirewallConfig{
		BlockRules: []OldBlockRule{{Protocol: "tcp", DstIP: "1.2.3.4", DstPort: "443"}},
		Variables:  map[string]interface{}{"vacation": true, "limit": 42.0},
	}
	data, _ := json.Marshal(old)
	if err := os.WriteFile(FirewallConfigFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	if err := migratePfwRulesIPtoAddress(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if len(gFirewallConfig.Variables) != 2 {
		t.Fatalf("migration dropped variables: %+v", gFirewallConfig.Variables)
	}
	if gFirewallConfig.Variables["vacation"] != true {
		t.Errorf("variable lost in migration: %+v", gFirewallConfig.Variables)
	}
	if len(gFirewallConfig.BlockRules) != 1 || gFirewallConfig.BlockRules[0].Dst.IP != "1.2.3.4" {
		t.Errorf("block rule not migrated: %+v", gFirewallConfig.BlockRules)
	}
}

// a missing config file must still leave the mark maps initialized
func TestLoadFirewallRulesMissingFile(t *testing.T) {
	saveConfigGlobals(t)

	dir := t.TempDir()
	FirewallConfigFile = filepath.Join(dir, "does-not-exist.json")
	gFirewallConfig.IfaceMarkMap = IfaceMarkMapping{}

	if err := loadFirewallRules(); err == nil {
		t.Error("loadFirewallRules() = nil error for missing file")
	}
	if gFirewallConfig.IfaceMarkMap.Map == nil || gFirewallConfig.IfaceMarkMap.rmap == nil {
		t.Fatal("IfaceMarkMap not initialized after failed load")
	}

	FWmtx.Lock()
	idx := getIfaceMarkMap("testiface0")
	FWmtx.Unlock()
	if idx == "" {
		t.Error("getIfaceMarkMap returned empty index")
	}
}

// invalid DstPort values must be rejected
func TestForwardRuleDstPortValidation(t *testing.T) {
	saveConfigGlobals(t)
	FirewallConfigFile = filepath.Join(t.TempDir(), "rules.json")

	router := mux.NewRouter()
	router.HandleFunc("/forward", modifyForwardRules).Methods("DELETE", "PUT")

	doPut := func(fwd ForwardingRule) int {
		body, _ := json.Marshal(fwd)
		req := httptest.NewRequest(http.MethodPut, "/forward", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code
	}

	fwd := ForwardingRule{
		Protocol:        "tcp",
		OriginalDst:     Address{IP: "10.99.40.3"},
		OriginalDstPort: "80",
		Dst:             Address{IP: "10.99.40.4"},
		DstPort:         "abc",
	}
	fwd.Client = ClientIdentifier{SrcIP: "10.99.40.2"}

	if code := doPut(fwd); code != 400 {
		t.Errorf("invalid DstPort accepted: status %d, want 400", code)
	}

	fwd.DstPort = "8080"
	if code := doPut(fwd); code != 200 {
		t.Errorf("valid DstPort rejected: status %d", code)
	}
}

// "ip" addresses must not take a port, matching what executeUplinkCheck accepts
func TestVerifyAddress(t *testing.T) {
	cases := map[string]bool{
		"ip:1.2.3.4":      true,
		"tcp:1.2.3.4:80":  true,
		"ip:1.2.3.4:80":   false,
		"tcp:1.2.3.4":     false,
		"udp:1.2.3.4":     false,
		"tcp:bad:80":      false,
		"tcp:1.2.3.4:bad": false,
	}
	for addr, want := range cases {
		if got := verifyAddress(addr); got != want {
			t.Errorf("verifyAddress(%q) = %v, want %v", addr, got, want)
		}
	}
}
