/**
 * Copyright (C) Supernetworks, Inc - All Rights Reserved
 *
 * This source code is protected under international copyright law.  All rights
 * reserved and protected by the copyright holders.
 * This file is confidential and only available to authorized individuals with the
 * permission of the copyright holders.  If you encounter this file and do not have
 * permission, please contact the copyright holders and delete this file.
 */

package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
)

type OldBlockRule struct {
	PFWRule
	Protocol string
	DstIP    string
	DstPort  string
}

type OldForwardingRule struct {
	PFWRule
	Protocol string

	OriginalDstIP   string
	OriginalDstPort string

	DstIP        string
	DstPort      string
	DstInterface string
}

type OldFirewallConfig struct {
	ForwardingRules []OldForwardingRule
	BlockRules      []OldBlockRule
	TagRules        []TagRule
	GroupRules      []GroupRule
	Variables       map[string]interface{}
	SiteVPNs        []SiteVPN
	APIToken        string
	IfaceMarkMap    IfaceMarkMapping
}

func makeBackup(suffix string) bool {
	backupFile := FirewallConfigFile + "." + suffix

	if _, err := os.Stat(backupFile); os.IsNotExist(err) {
		// Open original file
		originalFile, err := os.Open(FirewallConfigFile)
		if err != nil {
			return true
		}
		defer originalFile.Close()

		// Create backup file
		newFile, err := os.Create(backupFile)
		if err != nil {
			return true
		}
		defer newFile.Close()

		// Copy the contents of the original file to the backup file
		_, err = io.Copy(newFile, originalFile)
		if err != nil {
			return true
		}
		return true
	}

	// already made a backup and migrated
	return false
}

func MigrateBlockRule(oldRule OldBlockRule) BlockRule {
	return BlockRule{
		PFWRule:  oldRule.PFWRule,
		Protocol: oldRule.Protocol,
		Dst: Address{
			IP: oldRule.DstIP,
		},
		DstPort: oldRule.DstPort,
	}
}

func MigrateFwdRule(oldRule OldForwardingRule) ForwardingRule {
	return ForwardingRule{
		PFWRule:  oldRule.PFWRule,
		Protocol: oldRule.Protocol,
		OriginalDst: Address{
			IP: oldRule.OriginalDstIP,
		},
		OriginalDstPort: oldRule.OriginalDstPort,
		Dst: Address{
			IP: oldRule.DstIP,
		},
		DstPort:      oldRule.DstPort,
		DstInterface: oldRule.DstInterface,
	}
}

func migratePfwRulesIPtoAddress() error {
	if makeBackup("migrate-address") == false {
		//already made migration
		return nil
	}

	var old = OldFirewallConfig{[]OldForwardingRule{}, []OldBlockRule{}, []TagRule{}, []GroupRule{}, map[string]interface{}{}, []SiteVPN{}, "", IfaceMarkMapping{}}

	data, err := ioutil.ReadFile(FirewallConfigFile)
	if err != nil {
		return err
	} else {
		err := json.Unmarshal(data, &old)
		if err != nil {
			return err
		}
	}

	gFirewallConfig = FirewallConfig{TagRules: old.TagRules,
		GroupRules:   old.GroupRules,
		SiteVPNs:     old.SiteVPNs,
		APIToken:     old.APIToken,
		IfaceMarkMap: old.IfaceMarkMap, //technically new but ok
	}

	//now migrate the block rules
	for _, block := range old.BlockRules {
		gFirewallConfig.BlockRules = append(gFirewallConfig.BlockRules, MigrateBlockRule(block))
	}

	for _, fwd := range old.ForwardingRules {
		gFirewallConfig.ForwardingRules = append(gFirewallConfig.ForwardingRules, MigrateFwdRule(fwd))
	}

	saveFirewallRulesLocked()
	return nil
}
