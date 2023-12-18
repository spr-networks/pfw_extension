/**
 * Copyright (C) 2023 Supernetworks, Inc - All Rights Reserved
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
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/spr-networks/sprbus"
)

type TaskConfig struct {
	PFWRule
}

type WifiScanConfig struct {
	TaskConfig
	Interfaces []string
}

type UplinkCheckConfig struct {
	TaskConfig
	Addresses []string
}

type PFWTaskConfig struct {
	WiFiScan    WifiScanConfig
	UplinkCheck UplinkCheckConfig
}

var gTaskConfig = PFWTaskConfig{
	WifiScanConfig{},
	UplinkCheckConfig{},
}

var Taskmtx sync.RWMutex

var TaskConfigFile = TEST_PREFIX + "/configs/pfw/tasks.json"

func (config *WifiScanConfig) Validate() error {
	if len(config.Interfaces) == 0 {
		return fmt.Errorf("Need at least one interface")
	}

	return nil
}

func verifyAddress(str string) bool {
	parts := strings.SplitN(str, ":", 3)
	if len(parts) != 2 && len(parts) != 3 { // Must have 2 or 3 parts
		return false
	}

	if parts[0] != "tcp" && parts[0] != "ip" { // Must start with "tcp" or "ip"
		return false
	}

	if parts[0] == "tcp" && len(parts) != 3 { // "tcp" needs a port
		return false
	}

	// Validate IP address
	ip := net.ParseIP(parts[1])
	if ip == nil {
		return false
	}

	// Validate port if present
	if len(parts) == 3 {
		_, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil {
			return false
		}
	}

	return true
}

func (config *UplinkCheckConfig) Validate() error {
	if len(config.Addresses) == 0 {
		return fmt.Errorf("Need at least one address")
	}

	for i, addr := range config.Addresses {
		if !verifyAddress(addr) {
			return fmt.Errorf("Invalid address at index ", i)
		}
	}

	return nil
}

func loadTaskConfigLocked() error {
	data, err := ioutil.ReadFile(TaskConfigFile)
	if err != nil {
		return err
	} else {
		err := json.Unmarshal(data, &gTaskConfig)
		if err != nil {
			return err
		}
	}

	return nil
}

func saveTaskConfigLocked() {
	file, _ := json.MarshalIndent(gTaskConfig, "", " ")
	err := ioutil.WriteFile(TaskConfigFile, file, 0600)
	if err != nil {
		fmt.Println(err)
	}
}

func runTaskOnce(w http.ResponseWriter, r *http.Request) {
	Taskmtx.RLock()
	defer Taskmtx.RUnlock()
	vars := mux.Vars(r)
	taskName, ok := vars["task"]
	if !ok {
		http.Error(w, "invalid task", 400)
		return
	}

	var err error
	//NOTE: This executes regardless of conditions, or disabled status
	switch taskName {
	case "wifi-scan":
		err = executeWifiScan(gTaskConfig.WiFiScan)
	case "uplink-check":
		err = executeUplinkCheck(gTaskConfig.UplinkCheck)
	default:
		http.Error(w, "invalid task", 400)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), 400)
	}
}

func configureWifiScan(w http.ResponseWriter, r *http.Request, config WifiScanConfig) {
	err := config.Validate()
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	gTaskConfig.WiFiScan = config
	saveTaskConfigLocked()
}

func configureUplinkCheck(w http.ResponseWriter, r *http.Request, config UplinkCheckConfig) {
	err := config.Validate()
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	gTaskConfig.UplinkCheck = config
	saveTaskConfigLocked()
}

func getTaskConfig(w http.ResponseWriter, r *http.Request) {
	Taskmtx.Lock()
	defer Taskmtx.Unlock()

	x := gTaskConfig

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(x)
}

func configTask(w http.ResponseWriter, r *http.Request) {
	Taskmtx.Lock()
	defer Taskmtx.Unlock()

	vars := mux.Vars(r)
	taskName, ok := vars["task"]
	if !ok {
		http.Error(w, "invalid task", 400)
		return
	}

	var err error
	switch taskName {
	case "wifi-scan":
		wifiScanConfig := WifiScanConfig{}
		err = json.NewDecoder(r.Body).Decode(&wifiScanConfig)
		if err == nil {
			configureWifiScan(w, r, wifiScanConfig)
			return
		}
	case "uplink-check":
		uplinkCheck := UplinkCheckConfig{}
		err = json.NewDecoder(r.Body).Decode(&uplinkCheck)
		if err == nil {
			configureUplinkCheck(w, r, uplinkCheck)
			return
		}
	default:
		http.Error(w, "invalid task", 400)
		return
	}

	if err != nil {
		http.Error(w, "Failed to decode input", 400)
	}

}

func executeWifiScan(rule WifiScanConfig) error {
	for _, iface := range rule.Interfaces {
		err := exec.Command("ip", "link", "set", "dev", iface, "up").Run()
		if err != nil {
			return err
		}
		cmd := exec.Command("iw", "dev", iface, "scan")
		data, err := cmd.Output()
		if err != nil {
			return err
		}

		cmd = exec.Command("jc", "--iw-scan")

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return err
		}

		go func() {
			defer stdin.Close()
			io.WriteString(stdin, string(data))
		}()

		stdout, err := cmd.Output()
		if err != nil {
			return err
		}
		ret := []map[string]interface{}{}
		err = json.Unmarshal(stdout, &ret)
		if err != nil {
			return err
		}

		if len(ret) > 0 {
			//okay now send to sprbus
			sprbus.Publish("task:wifi-scan", ret[0])
		}

	}

	return nil
}

var gLastUplinkState = make(map[string]string)

func executeUplinkCheck(rule UplinkCheckConfig) error {

	for _, addr := range rule.Addresses {

		//only report uplink transition up/down.
		newState := "Up"

		parts := strings.Split(addr, ":")
		if len(parts) == 2 && strings.HasPrefix(addr, "ip:") {
			if !pingCheck(parts[1]) {
				newState = "Down"
			}
		} else if len(parts) == 3 && strings.HasPrefix(addr, "tcp:") {
			if !tcpCheck(parts[1], parts[2]) {
				newState = "Down"
			}
		} else {
			return fmt.Errorf("Unknown address type", addr)
		}

		entry, exists := gLastUplinkState[addr]
		doUpdate := true
		if exists && entry == newState {
			doUpdate = false
		}
		if doUpdate {
			ret := map[string]string{}
			ret["State"] = newState
			ret["Address"] = addr
			gLastUplinkState[addr] = newState
			sprbus.Publish("task-uplink-check:changed", ret)
		}

	}

	return nil
}

func executeTasks() {

	{
		rule := gTaskConfig.WiFiScan
		if ruleActive(rule.Disabled, rule.Condition, rule.Time, rule.Expiration) {
			//run the wifi scan
			executeWifiScan(rule)
		}

	}

	{
		rule := gTaskConfig.UplinkCheck
		if ruleActive(rule.Disabled, rule.Condition, rule.Time, rule.Expiration) {
			//run the uplink check
			executeUplinkCheck(rule)
		}

	}

}

func runTasks() {

	Taskmtx.Lock()
	loadTaskConfigLocked()
	Taskmtx.Unlock()

	runTimer := func() {
		ticker := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-ticker.C:
				//every 1s check the firewall rules
				Taskmtx.RLock()
				executeTasks()
				Taskmtx.RUnlock()
			}
		}
	}

	go runTimer()
}
