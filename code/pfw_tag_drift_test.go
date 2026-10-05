//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestForwardTagRemovalDrift(t *testing.T) {
	setupSiteIface(t, "site9")
	resetForwardRules(t)

	oldDevFile := DevicesPublicConfigFile
	oldInstalled := installedForwards
	devFile := filepath.Join(t.TempDir(), "devices-public.json")
	DevicesPublicConfigFile = devFile
	installedForwards = map[string]installedFwd{}
	t.Cleanup(func() {
		DevicesPublicConfigFile = oldDevFile
		installedForwards = oldInstalled
	})

	writeDevs := func(tags []string) {
		devs := map[string]DeviceEntry{
			"aa:bb:cc:dd:ee:ff": {RecentIP: "10.99.9.5", DeviceTags: tags},
		}
		b, _ := json.Marshal(devs)
		if err := os.WriteFile(devFile, b, 0600); err != nil {
			t.Fatal(err)
		}
	}

	FWmtx.Lock()
	gFirewallConfig.ForwardingRules = []ForwardingRule{{
		PFWRule:         PFWRule{Client: ClientIdentifier{Tag: "mitmtest"}},
		Protocol:        "tcp",
		OriginalDst:     Address{IP: "0.0.0.0/0"},
		OriginalDstPort: "80",
		DstInterface:    "site9",
	}}
	FWmtx.Unlock()

	writeDevs([]string{"mitmtest"})
	reconcileNow()
	if !mapHas(t, "inet", "mangle", "site_forward_tcp_port_mangle", "10.99.9.5") {
		t.Fatal("forwarding element not installed for tagged device")
	}

	writeDevs([]string{})
	reconcileNow()
	if mapHas(t, "inet", "mangle", "site_forward_tcp_port_mangle", "10.99.9.5") {
		t.Error("stale forwarding element remained after device tag was removed")
	}
}

func TestBlockTagRemovalDrift(t *testing.T) {
	oldBlocks := gFirewallConfig.BlockRules
	oldDevFile := DevicesPublicConfigFile
	oldInstalled := installedBlocks
	devFile := filepath.Join(t.TempDir(), "devices-public.json")
	DevicesPublicConfigFile = devFile
	installedBlocks = map[string]installedBlk{}
	t.Cleanup(func() {
		FWmtx.Lock()
		gFirewallConfig.BlockRules = oldBlocks
		FWmtx.Unlock()
		DevicesPublicConfigFile = oldDevFile
		installedBlocks = oldInstalled
	})

	writeDevs := func(tags []string) {
		devs := map[string]DeviceEntry{
			"aa:bb:cc:dd:ee:01": {RecentIP: "10.99.9.6", DeviceTags: tags},
		}
		b, _ := json.Marshal(devs)
		if err := os.WriteFile(devFile, b, 0600); err != nil {
			t.Fatal(err)
		}
	}

	FWmtx.Lock()
	gFirewallConfig.BlockRules = []BlockRule{{
		PFWRule:  PFWRule{Client: ClientIdentifier{Tag: "mitmtest"}},
		Protocol: "tcp",
		Dst:      Address{IP: "1.2.3.4"},
		DstPort:  "443",
	}}
	FWmtx.Unlock()

	writeDevs([]string{"mitmtest"})
	reconcileNow()
	if !mapHas(t, "inet", "filter", "fwd_block", "10.99.9.6") {
		t.Fatal("block element not installed for tagged device")
	}

	writeDevs([]string{})
	reconcileNow()
	if mapHas(t, "inet", "filter", "fwd_block", "10.99.9.6") {
		t.Error("stale block element remained after device tag was removed")
	}
}

func TestBlockDoesNotFlushSharedMap(t *testing.T) {
	oldBlocks := gFirewallConfig.BlockRules
	oldDevFile := DevicesPublicConfigFile
	oldInstalled := installedBlocks
	devFile := filepath.Join(t.TempDir(), "devices-public.json")
	DevicesPublicConfigFile = devFile
	installedBlocks = map[string]installedBlk{}
	t.Cleanup(func() {
		FWmtx.Lock()
		gFirewallConfig.BlockRules = oldBlocks
		FWmtx.Unlock()
		DevicesPublicConfigFile = oldDevFile
		installedBlocks = oldInstalled
		nftRun(t, "delete", "element", "inet", "filter", "fwd_block",
			"{ 10.88.0.1 . 9.9.9.9 . 6 . 5555 }")
	})

	devs := map[string]DeviceEntry{
		"aa:bb:cc:dd:ee:02": {RecentIP: "10.99.9.7", DeviceTags: []string{"mitmtest"}},
	}
	b, _ := json.Marshal(devs)
	if err := os.WriteFile(devFile, b, 0600); err != nil {
		t.Fatal(err)
	}

	nftRun(t, "add", "element", "inet", "filter", "fwd_block",
		"{ 10.88.0.1 . 9.9.9.9 . 6 . 5555 : drop }")

	FWmtx.Lock()
	gFirewallConfig.BlockRules = []BlockRule{{
		PFWRule:  PFWRule{Client: ClientIdentifier{Tag: "mitmtest"}},
		Protocol: "tcp",
		Dst:      Address{IP: "1.2.3.4"},
		DstPort:  "443",
	}}
	FWmtx.Unlock()

	reconcileNow()
	reconcileNow()

	if !mapHas(t, "inet", "filter", "fwd_block", "9.9.9.9") {
		t.Error("pfw block apply wiped a foreign fwd_block element (base API rule)")
	}
}
