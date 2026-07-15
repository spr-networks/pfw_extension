//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestBlockOrphanCleanupAcrossRestart(t *testing.T) {

	oldBlocks := gFirewallConfig.BlockRules
	oldInstalled := installedBlocks
	t.Cleanup(func() {
		FWmtx.Lock()
		gFirewallConfig.BlockRules = oldBlocks
		FWmtx.Unlock()
		installedBlocks = oldInstalled
		nftRun(t, "flush", "map", "inet", "filter", "fwd_block")
	})

	FWmtx.Lock()
	gFirewallConfig.BlockRules = []BlockRule{{
		PFWRule:  PFWRule{Client: ClientIdentifier{SrcIP: "10.99.9.9"}},
		Protocol: "tcp",
		Dst:      Address{IP: "9.8.7.6"},
		DstPort:  "443",
	}}
	FWmtx.Unlock()
	installedBlocks = map[string]installedBlk{}

	reconcileNow()
	if !mapHas(t, "inet", "filter", "fwd_block", "10.99.9.9") {
		t.Fatal("block element not installed")
	}

	FWmtx.Lock()
	gFirewallConfig.BlockRules = nil
	FWmtx.Unlock()
	installedBlocks = map[string]installedBlk{}
	loadInstalledState()

	reconcileNow()
	if mapHas(t, "inet", "filter", "fwd_block", "10.99.9.9") {
		t.Error("orphaned block element not cleaned up after simulated restart")
	}
}

func TestInactiveRuleResetsDNSOnce(t *testing.T) {
	setupSiteIface(t, "site9")
	resetForwardRules(t)

	oldDevFile := DevicesPublicConfigFile
	oldInstalled := installedForwards
	oldSiteDNS := siteDNSClients
	oldVPNs := gFirewallConfig.SiteVPNs
	oldUpdate := updateDeviceFunc
	devFile := filepath.Join(t.TempDir(), "devices-public.json")
	DevicesPublicConfigFile = devFile
	installedForwards = map[string]installedFwd{}
	siteDNSClients = map[string]string{}

	vpns := make([]SiteVPN, 10)
	vpns[9].DNS = "10.99.99.99"
	FWmtx.Lock()
	gFirewallConfig.SiteVPNs = vpns
	FWmtx.Unlock()

	var deviceWrites atomic.Int32
	updateDeviceFunc = func(string, DeviceEntry) {
		deviceWrites.Add(1)
	}
	t.Cleanup(func() {
		DevicesPublicConfigFile = oldDevFile
		installedForwards = oldInstalled
		siteDNSClients = oldSiteDNS
		FWmtx.Lock()
		gFirewallConfig.SiteVPNs = oldVPNs
		FWmtx.Unlock()
		updateDeviceFunc = oldUpdate
		nftRun(t, "flush", "map", "inet", "filter", "site_forward")
		nftRun(t, "flush", "map", "inet", "mangle", "site_forward_mangle")
	})

	devs := map[string]DeviceEntry{
		"aa:bb:cc:dd:ee:03": {RecentIP: "10.99.9.8"},
	}
	b, _ := json.Marshal(devs)
	if err := os.WriteFile(devFile, b, 0600); err != nil {
		t.Fatal(err)
	}

	rule := ForwardingRule{
		PFWRule:      PFWRule{Client: ClientIdentifier{SrcIP: "10.99.9.8"}},
		OriginalDst:  Address{IP: "0.0.0.0/0"},
		DstInterface: "site9",
	}

	FWmtx.Lock()
	gFirewallConfig.ForwardingRules = []ForwardingRule{rule}
	FWmtx.Unlock()

	reconcileNow()
	if !mapHas(t, "inet", "mangle", "site_forward_mangle", "10.99.9.8") {
		t.Fatal("forwarding element not installed")
	}
	if got := deviceWrites.Load(); got != 1 {
		t.Errorf("expected exactly 1 DNS-set device write after enable, got %d", got)
	}

	rule.Disabled = true
	FWmtx.Lock()
	gFirewallConfig.ForwardingRules = []ForwardingRule{rule}
	FWmtx.Unlock()

	reconcileNow()
	if mapHas(t, "inet", "mangle", "site_forward_mangle", "10.99.9.8") {
		t.Fatal("forwarding element not removed after disable")
	}

	after := deviceWrites.Load()
	if after != 2 {
		t.Errorf("expected exactly 1 DNS-reset device write after disable (2 total), got %d total", after)
	}

	reconcileNow()
	reconcileNow()
	reconcileNow()
	if got := deviceWrites.Load(); got != after {
		t.Errorf("inactive rule kept issuing device writes: %d -> %d", after, got)
	}
}

func TestTagRuleLifecycle(t *testing.T) {
	oldDevFile := DevicesPublicConfigFile
	oldApplied := appliedTags
	oldTagRules := gFirewallConfig.TagRules
	oldUpdate := updateDeviceFunc
	devFile := filepath.Join(t.TempDir(), "devices-public.json")
	DevicesPublicConfigFile = devFile
	appliedTags = map[string]map[string]bool{}
	t.Cleanup(func() {
		FWmtx.Lock()
		gFirewallConfig.TagRules = oldTagRules
		FWmtx.Unlock()
		DevicesPublicConfigFile = oldDevFile
		appliedTags = oldApplied
		updateDeviceFunc = oldUpdate
	})

	writeDevs := func(devs map[string]DeviceEntry) {
		b, _ := json.Marshal(devs)
		if err := os.WriteFile(devFile, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	updateDeviceFunc = func(identity string, entry DeviceEntry) {
		devs, _ := APIDevices()
		devs[identity] = entry
		writeDevs(devs)
	}

	writeDevs(map[string]DeviceEntry{
		"aa:bb:cc:dd:ee:04": {RecentIP: "10.99.9.4", Groups: []string{"lan"}, DeviceTags: []string{"manual"}},
	})

	FWmtx.Lock()
	gFirewallConfig.TagRules = []TagRule{{
		PFWRule: PFWRule{Client: ClientIdentifier{Group: "lan"}},
		Tags:    []string{"needstag"},
	}}
	FWmtx.Unlock()

	hasTag := func(tag string) bool {
		devs, err := APIDevices()
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range devs["aa:bb:cc:dd:ee:04"].DeviceTags {
			if v == tag {
				return true
			}
		}
		return false
	}

	reconcileNow()
	if !hasTag("needstag") {
		t.Fatal("active tag rule did not assign the tag")
	}

	FWmtx.Lock()
	gFirewallConfig.TagRules = nil
	FWmtx.Unlock()
	reconcileNow()
	if hasTag("needstag") {
		t.Error("deleted tag rule left its tag on the device")
	}
	if !hasTag("manual") {
		t.Error("manually-set tag was removed")
	}
}
