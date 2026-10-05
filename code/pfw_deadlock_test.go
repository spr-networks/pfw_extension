//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func tryLockWithTimeout(try func() bool, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for !try() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

func TestApplyTagRuleNoDeadlock(t *testing.T) {
	oldTag := gFirewallConfig.TagRules
	oldGroup := gFirewallConfig.GroupRules
	oldFwd := gFirewallConfig.ForwardingRules
	oldBlk := gFirewallConfig.BlockRules
	oldDevFile := DevicesPublicConfigFile
	oldUpdate := updateDeviceFunc
	devFile := filepath.Join(t.TempDir(), "devices-public.json")
	DevicesPublicConfigFile = devFile

	var reentryBlocked atomic.Bool
	updateDeviceFunc = func(identity string, entry DeviceEntry) {
		if !tryLockWithTimeout(FWmtx.TryRLock, 10*time.Second) {
			reentryBlocked.Store(true)
			return
		}
		FWmtx.RUnlock()
	}

	t.Cleanup(func() {
		DevicesPublicConfigFile = oldDevFile
		updateDeviceFunc = oldUpdate
		if !tryLockWithTimeout(FWmtx.TryLock, 5*time.Second) {
			return
		}
		gFirewallConfig.TagRules = oldTag
		gFirewallConfig.GroupRules = oldGroup
		gFirewallConfig.ForwardingRules = oldFwd
		gFirewallConfig.BlockRules = oldBlk
		FWmtx.Unlock()
	})

	devs := map[string]DeviceEntry{
		"aa:bb:cc:dd:ee:99": {RecentIP: "10.99.9.99", Groups: []string{"lan"}},
	}
	b, _ := json.Marshal(devs)
	if err := os.WriteFile(devFile, b, 0600); err != nil {
		t.Fatal(err)
	}

	FWmtx.Lock()
	gFirewallConfig.ForwardingRules = nil
	gFirewallConfig.BlockRules = nil
	gFirewallConfig.GroupRules = nil
	gFirewallConfig.TagRules = []TagRule{{
		PFWRule: PFWRule{Client: ClientIdentifier{Group: "lan"}},
		Tags:    []string{"needstag"},
	}}
	FWmtx.Unlock()

	done := make(chan struct{})
	go func() {
		reconcileNow()
		close(done)
	}()

	select {
	case <-done:
		if reentryBlocked.Load() {
			t.Fatal("device update ran while FWmtx was write-held: the device API callback path would deadlock")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("apply deadlocked while applying a tag-assignment rule")
	}
}
