//go:build linux

package main

import (
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func setupSiteIface(t *testing.T, iface string) {
	t.Helper()
	exec.Command("ip", "link", "add", iface, "type", "dummy").Run()
	exec.Command("ip", "link", "set", iface, "up").Run()
	t.Cleanup(func() {
		exec.Command("ip", "link", "del", iface).Run()
	})
}

func forwardTestRouter() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/forward", withConfigMutation(modifyForwardRules)).Methods("DELETE", "PUT")
	router.HandleFunc("/forward/{index:[0-9]+}", withConfigMutation(modifyForwardRules)).Methods("DELETE", "PUT")
	return router
}

func forwardReq(t *testing.T, router *mux.Router, method, path, body string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("%s %s = %d: %s", method, path, w.Code, w.Body.String())
	}
}

func resetForwardRules(t *testing.T) {
	FWmtx.Lock()
	saved := gFirewallConfig.ForwardingRules
	gFirewallConfig.ForwardingRules = []ForwardingRule{}
	FWmtx.Unlock()
	t.Cleanup(func() {
		FWmtx.Lock()
		gFirewallConfig.ForwardingRules = saved
		FWmtx.Unlock()
	})
}

func mapHas(t *testing.T, family, table, mapName, marker string) bool {
	t.Helper()
	return strings.Contains(nftDump(t, "list", "map", family, table, mapName), marker)
}

func TestForwardEditPortToggleDNAT(t *testing.T) {
	resetForwardRules(t)
	router := forwardTestRouter()
	marker := "10.99.7.1"

	t.Cleanup(func() {
		resetForwardRules(t)
		for _, m := range []string{"dnat_tcp_ipmap", "dnat_tcp_portmap", "dnat_tcp_anymap"} {
			nftRun(t, "flush", "map", "inet", "nat", m)
		}
	})

	rangeBody := `{"Protocol":"tcp","Client":{"SrcIP":"10.99.7.1"},"OriginalDst":{"IP":"10.99.7.2"},"OriginalDstPort":"0-100","Dst":{"IP":"10.99.7.3"},"DstPort":"80"}`
	anyBody := `{"Protocol":"tcp","Client":{"SrcIP":"10.99.7.1"},"OriginalDst":{"IP":"10.99.7.2"},"OriginalDstPort":"","Dst":{"IP":"10.99.7.3"}}`
	fullRangeBody := `{"Protocol":"tcp","Client":{"SrcIP":"10.99.7.1"},"OriginalDst":{"IP":"10.99.7.2"},"OriginalDstPort":"0-65535","Dst":{"IP":"10.99.7.3"},"DstPort":"80"}`

	forwardReq(t, router, "PUT", "/forward", rangeBody)
	reconcileNow()
	if !mapHas(t, "inet", "nat", "dnat_tcp_ipmap", marker) {
		t.Fatal("range rule not installed in dnat_tcp_ipmap")
	}

	forwardReq(t, router, "PUT", "/forward/0", anyBody)
	reconcileNow()
	if mapHas(t, "inet", "nat", "dnat_tcp_ipmap", marker) {
		t.Error("stale range entry left in dnat_tcp_ipmap after edit to any")
	}
	if mapHas(t, "inet", "nat", "dnat_tcp_portmap", marker) {
		t.Error("stale range entry left in dnat_tcp_portmap after edit to any")
	}
	if !mapHas(t, "inet", "nat", "dnat_tcp_anymap", marker) {
		t.Error("any rule not installed in dnat_tcp_anymap")
	}

	forwardReq(t, router, "PUT", "/forward/0", rangeBody)
	reconcileNow()
	if mapHas(t, "inet", "nat", "dnat_tcp_anymap", marker) {
		t.Error("stale any entry left in dnat_tcp_anymap after edit to range")
	}
	if !mapHas(t, "inet", "nat", "dnat_tcp_ipmap", marker) {
		t.Error("range rule not reinstalled in dnat_tcp_ipmap")
	}

	forwardReq(t, router, "PUT", "/forward/0", fullRangeBody)
	reconcileNow()
	dump := nftDump(t, "list", "map", "inet", "nat", "dnat_tcp_ipmap")
	if strings.Contains(dump, "0-100") {
		t.Error("stale 0-100 entry left in dnat_tcp_ipmap after edit to 0-65535")
	}
	if !strings.Contains(dump, marker) {
		t.Error("full range rule not installed in dnat_tcp_ipmap")
	}

	forwardReq(t, router, "PUT", "/forward/0", rangeBody)
	reconcileNow()
	if !mapHas(t, "inet", "nat", "dnat_tcp_ipmap", marker) {
		t.Error("range rule not reinstalled after edit")
	}

	forwardReq(t, router, "DELETE", "/forward/0", "")
	for _, m := range []string{"dnat_tcp_ipmap", "dnat_tcp_portmap", "dnat_tcp_anymap"} {
		if mapHas(t, "inet", "nat", m, marker) {
			t.Errorf("stale entry left in %s after delete", m)
		}
	}
}

func TestForwardEditPortToggleSite(t *testing.T) {
	setupSiteIface(t, "site9")
	resetForwardRules(t)
	router := forwardTestRouter()
	marker := "10.99.8.1"

	t.Cleanup(func() {
		resetForwardRules(t)
		for _, m := range []string{"site_forward_mangle", "site_forward_tcp_port_mangle"} {
			nftRun(t, "flush", "map", "inet", "mangle", m)
		}
		nftRun(t, "flush", "map", "inet", "filter", "site_forward")
		nftRun(t, "flush", "map", "inet", "filter", "site_forward_tcp_port")
	})

	portBody := `{"Protocol":"tcp","Client":{"SrcIP":"10.99.8.1"},"OriginalDst":{"IP":"10.99.8.2"},"OriginalDstPort":"0-100","DstInterface":"site9"}`
	anyBody := `{"Client":{"SrcIP":"10.99.8.1"},"OriginalDst":{"IP":"10.99.8.2"},"DstInterface":"site9"}`

	forwardReq(t, router, "PUT", "/forward", portBody)
	reconcileNow()
	if !mapHas(t, "inet", "mangle", "site_forward_tcp_port_mangle", marker) {
		t.Fatal("port rule not installed in site_forward_tcp_port_mangle")
	}

	forwardReq(t, router, "PUT", "/forward/0", anyBody)
	reconcileNow()
	if mapHas(t, "inet", "mangle", "site_forward_tcp_port_mangle", marker) {
		t.Error("stale port entry left in site_forward_tcp_port_mangle after edit to any")
	}
	if !mapHas(t, "inet", "mangle", "site_forward_mangle", marker) {
		t.Error("any rule not installed in site_forward_mangle")
	}

	forwardReq(t, router, "PUT", "/forward/0", portBody)
	reconcileNow()
	if mapHas(t, "inet", "mangle", "site_forward_mangle", marker) {
		t.Error("stale any entry left in site_forward_mangle after edit to port rule")
	}
	if !mapHas(t, "inet", "mangle", "site_forward_tcp_port_mangle", marker) {
		t.Error("port rule not reinstalled in site_forward_tcp_port_mangle")
	}

	forwardReq(t, router, "DELETE", "/forward/0", "")
	for _, m := range []string{"site_forward_mangle", "site_forward_tcp_port_mangle"} {
		if mapHas(t, "inet", "mangle", m, marker) {
			t.Errorf("stale entry left in %s after delete", m)
		}
	}
}
