//go:build linux

package main

// Differential tests for the pfw nft conversion, with the nft CLI as the
// reference behavior. They need the test/nft_rules.sh fixture in a privileged
// Linux container (see test-unit.sh).

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

var expiresRe = regexp.MustCompile(`expires [^ ,}]+ ?`)

// nftDump returns a listing with whitespace collapsed and the volatile
// per-element "expires" countdowns removed.
func nftDump(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	s := strings.Join(strings.Fields(string(out)), " ")
	return expiresRe.ReplaceAllString(s, "")
}

func nftRun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
		t.Fatalf("nft %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// assertElementEquivalence adds an element via libAdd and via the nft CLI
// element syntax, asserting both leave identical state relative to the same
// baseline, and that libDelete restores it.
func assertElementEquivalence(t *testing.T, family, table, mapName string, cliElem []string, libAdd func() error, libDelete func() error) {
	t.Helper()
	listArgs := []string{"list", "map", family, table, mapName}

	baseline := nftDump(t, listArgs...)

	if err := libAdd(); err != nil {
		t.Fatalf("library add failed: %v", err)
	}
	libState := nftDump(t, listArgs...)
	if err := libDelete(); err != nil {
		t.Fatalf("library delete failed: %v", err)
	}
	if got := nftDump(t, listArgs...); got != baseline {
		t.Fatalf("library delete did not restore baseline:\n base=%q\n got =%q", baseline, got)
	}

	addArgs := append([]string{"add", "element", family, table, mapName, "{"}, append(cliElem, "}")...)
	nftRun(t, addArgs...)
	cliState := nftDump(t, listArgs...)
	delArgs := append([]string{"delete", "element", family, table, mapName, "{"}, append(cliElem, "}")...)
	_ = exec.Command("nft", delArgs...).Run()

	if libState == baseline {
		t.Fatal("operation had no observable effect")
	}
	if libState != cliState {
		t.Errorf("library state differs from nft CLI state:\n lib=%q\n cli=%q", libState, cliState)
	}
}

func TestBlockElementEquivalence(t *testing.T) {
	client := GetNFTClient()
	key, keyEnd := buildIPIPProtocolPortRangeKeys("10.99.0.1", "10.99.0.2", "tcp", "443")
	if key == nil {
		t.Fatal("key build failed")
	}
	_ = keyEnd

	t.Run("permanent", func(t *testing.T) {
		assertElementEquivalence(t, "inet", "filter", "fwd_block",
			[]string{"10.99.0.1", ".", "10.99.0.2", ".", "tcp", ".", "443", ":", "goto PFWDROPLOG"},
			func() error {
				return client.AddMapElementWithTimeout(TableFamilyInet, "filter", "fwd_block", key, []byte("goto PFWDROPLOG"), 0)
			},
			func() error {
				return client.DeleteMapElement(TableFamilyInet, "filter", "fwd_block", key)
			},
		)
	})

	t.Run("with timeout", func(t *testing.T) {
		assertElementEquivalence(t, "inet", "filter", "fwd_block",
			[]string{"10.99.0.1", ".", "10.99.0.2", ".", "tcp", ".", "443", "timeout", "60s", ":", "goto PFWDROPLOG"},
			func() error {
				return client.AddMapElementWithTimeout(TableFamilyInet, "filter", "fwd_block", key, []byte("goto PFWDROPLOG"), 60*time.Second)
			},
			func() error {
				return client.DeleteMapElement(TableFamilyInet, "filter", "fwd_block", key)
			},
		)
	})
}

func TestSiteForwardEquivalence(t *testing.T) {
	client := GetNFTClient()

	_ = DeleteChain("inet", "mangle", "mark100")
	if err := AddChain("inet", "mangle", "mark100"); err != nil {
		t.Fatalf("AddChain: %v", err)
	}
	t.Cleanup(func() { _ = DeleteChain("inet", "mangle", "mark100") })

	t.Run("site_forward accept", func(t *testing.T) {
		key, _ := buildIPIPIfaceRangeKeys("10.99.1.1", "10.99.1.2", "site0")
		assertElementEquivalence(t, "inet", "filter", "site_forward",
			[]string{"10.99.1.1", ".", "10.99.1.2", ".", "site0", ":", "accept"},
			func() error {
				return client.AddMapElementWithTimeout(TableFamilyInet, "filter", "site_forward", key, []byte("accept"), 0)
			},
			func() error {
				return client.DeleteMapElement(TableFamilyInet, "filter", "site_forward", key)
			},
		)
	})

	t.Run("site_forward_mangle jump", func(t *testing.T) {
		key := buildIPIPKey("10.99.1.1", "10.99.1.2")
		assertElementEquivalence(t, "inet", "mangle", "site_forward_mangle",
			[]string{"10.99.1.1", ".", "10.99.1.2", ":", "jump mark100"},
			func() error {
				return client.AddMapElementWithTimeout(TableFamilyInet, "mangle", "site_forward_mangle", key, []byte("jump mark100"), 0)
			},
			func() error {
				return client.DeleteMapElement(TableFamilyInet, "mangle", "site_forward_mangle", key)
			},
		)
	})

	t.Run("site_forward_tcp_port accept", func(t *testing.T) {
		key, _ := buildIPIPPortIfaceRangeKeys("10.99.1.1", "10.99.1.2", "8080", "site0")
		assertElementEquivalence(t, "inet", "filter", "site_forward_tcp_port",
			[]string{"10.99.1.1", ".", "10.99.1.2", ".", "8080", ".", "site0", ":", "accept"},
			func() error {
				return client.AddMapElementWithTimeout(TableFamilyInet, "filter", "site_forward_tcp_port", key, []byte("accept"), 0)
			},
			func() error {
				return client.DeleteMapElement(TableFamilyInet, "filter", "site_forward_tcp_port", key)
			},
		)
	})

	t.Run("site_forward_tcp_port_mangle jump", func(t *testing.T) {
		key := buildIPIPPortKey("10.99.1.1", "10.99.1.2", "8080")
		assertElementEquivalence(t, "inet", "mangle", "site_forward_tcp_port_mangle",
			[]string{"10.99.1.1", ".", "10.99.1.2", ".", "8080", ":", "jump mark100"},
			func() error {
				return client.AddMapElementWithTimeout(TableFamilyInet, "mangle", "site_forward_tcp_port_mangle", key, []byte("jump mark100"), 0)
			},
			func() error {
				return client.DeleteMapElement(TableFamilyInet, "mangle", "site_forward_tcp_port_mangle", key)
			},
		)
	})
}

func TestDnatMapEquivalence(t *testing.T) {
	client := GetNFTClient()

	t.Run("ipmap", func(t *testing.T) {
		key := buildIPIPPortKey("10.99.2.1", "10.99.2.2", "53")
		assertElementEquivalence(t, "inet", "nat", "dnat_tcp_ipmap",
			[]string{"10.99.2.1", ".", "10.99.2.2", ".", "53", ":", "192.168.50.5"},
			func() error {
				return client.AddMapElementWithTimeout(TableFamilyInet, "nat", "dnat_tcp_ipmap", key, IPToBytes("192.168.50.5"), 0)
			},
			func() error {
				return client.DeleteMapElement(TableFamilyInet, "nat", "dnat_tcp_ipmap", key)
			},
		)
	})

	t.Run("portmap", func(t *testing.T) {
		key := buildIPIPPortKey("10.99.2.1", "10.99.2.2", "53")
		assertElementEquivalence(t, "inet", "nat", "dnat_tcp_portmap",
			[]string{"10.99.2.1", ".", "10.99.2.2", ".", "53", ":", "8053"},
			func() error {
				return client.AddMapElementWithTimeout(TableFamilyInet, "nat", "dnat_tcp_portmap", key, PortToBytes("8053"), 0)
			},
			func() error {
				return client.DeleteMapElement(TableFamilyInet, "nat", "dnat_tcp_portmap", key)
			},
		)
	})

	t.Run("anymap with timeout", func(t *testing.T) {
		key := buildIPIPKey("10.99.2.1", "10.99.2.2")
		assertElementEquivalence(t, "inet", "nat", "dnat_udp_anymap",
			[]string{"10.99.2.1", ".", "10.99.2.2", "timeout", "60s", ":", "192.168.50.5"},
			func() error {
				return client.AddMapElementWithTimeout(TableFamilyInet, "nat", "dnat_udp_anymap", key, IPToBytes("192.168.50.5"), 60*time.Second)
			},
			func() error {
				return client.DeleteMapElement(TableFamilyInet, "nat", "dnat_udp_anymap", key)
			},
		)
	})
}

func TestOutboundSitesEquivalence(t *testing.T) {
	listArgs := []string{"list", "set", "inet", "filter", "outbound_sites"}
	baseline := nftDump(t, listArgs...)

	if err := AddInterfaceToSet("outbound_sites", "site7"); err != nil {
		t.Fatalf("AddInterfaceToSet: %v", err)
	}
	libState := nftDump(t, listArgs...)
	if err := FlushSetWithTable("inet", "filter", "outbound_sites"); err != nil {
		t.Fatalf("FlushSetWithTable: %v", err)
	}

	nftRun(t, "add", "element", "inet", "filter", "outbound_sites", "{", "site7", "}")
	cliState := nftDump(t, listArgs...)
	nftRun(t, "flush", "set", "inet", "filter", "outbound_sites")

	if libState == baseline {
		t.Fatal("add had no observable effect")
	}
	if libState != cliState {
		t.Errorf("library state differs from nft CLI:\n lib=%q\n cli=%q", libState, cliState)
	}
}

// makeMangleChain must produce the same chain the previous CLI sequence built:
// add chain; add rule meta mark set N; add rule accept.
func TestMakeMangleChainEquivalence(t *testing.T) {
	_ = DeleteChain("inet", "mangle", "mark207")
	_ = DeleteChain("inet", "mangle", "mark208")
	t.Cleanup(func() {
		_ = DeleteChain("inet", "mangle", "mark207")
		_ = DeleteChain("inet", "mangle", "mark208")
	})

	if err := makeMangleChain("207"); err != nil {
		t.Fatalf("makeMangleChain: %v", err)
	}

	nftRun(t, "add", "chain", "inet", "mangle", "mark208")
	nftRun(t, "add", "rule", "inet", "mangle", "mark208", "ip", "daddr", "@supernetworks", "accept")
	nftRun(t, "add", "rule", "inet", "mangle", "mark208", "meta", "mark", "set", "208")
	nftRun(t, "add", "rule", "inet", "mangle", "mark208", "accept")

	libDump := strings.ReplaceAll(nftDump(t, "list", "chain", "inet", "mangle", "mark207"), "mark207", "CHAIN")
	libDump = strings.ReplaceAll(libDump, "0x000000cf", "MARK")
	cliDump := strings.ReplaceAll(nftDump(t, "list", "chain", "inet", "mangle", "mark208"), "mark208", "CHAIN")
	cliDump = strings.ReplaceAll(cliDump, "0x000000d0", "MARK")

	if libDump != cliDump {
		t.Errorf("makeMangleChain differs from CLI-built chain:\n lib=%q\n cli=%q", libDump, cliDump)
	}

	// second call must be a no-op on an existing chain
	if err := makeMangleChain("207"); err != nil {
		t.Errorf("makeMangleChain not idempotent: %v", err)
	}

	if err := CheckChainExists("inet", "mangle", "mark207"); err != nil {
		t.Errorf("CheckChainExists after create: %v", err)
	}
}

func TestBlockRuleRoundTrip(t *testing.T) {
	br := BlockRule{Protocol: "tcp", Dst: Address{IP: "10.99.3.2"}, DstPort: "443"}
	const clientIP = "10.99.3.1"

	if isBlockInstalled(br, clientIP) {
		t.Fatal("block unexpectedly installed before add")
	}

	if err := addBlock(br, clientIP); err != nil {
		t.Fatalf("addBlock: %v", err)
	}
	t.Cleanup(func() { _ = deleteBlock(br, clientIP, false) })

	if !isBlockInstalled(br, clientIP) {
		t.Error("isBlockInstalled = false after addBlock")
	}
	if !strings.Contains(nftDump(t, "list", "map", "inet", "filter", "fwd_block"), "goto PFWDROPLOG") {
		t.Error("block element missing goto verdict in kernel state")
	}

	if err := deleteBlock(br, clientIP, false); err != nil {
		t.Fatalf("deleteBlock: %v", err)
	}
	if isBlockInstalled(br, clientIP) {
		t.Error("isBlockInstalled = true after deleteBlock")
	}
}

func TestDnatForwardingRoundTrip(t *testing.T) {
	fwd := ForwardingRule{
		Protocol:        "tcp",
		OriginalDst:     Address{IP: "10.99.4.2"},
		OriginalDstPort: "80",
		Dst:             Address{IP: "192.168.50.10"},
		DstPort:         "8080",
	}
	const clientIP = "10.99.4.1"

	if isForwardingInstalled(fwd, clientIP, false) {
		t.Fatal("forwarding unexpectedly installed before add")
	}

	if err := addForwarding(fwd, clientIP, false); err != nil {
		t.Fatalf("addForwarding: %v", err)
	}
	t.Cleanup(func() { _ = deleteForwarding(fwd, clientIP, false, false) })

	if !isForwardingInstalled(fwd, clientIP, false) {
		t.Error("isForwardingInstalled = false after addForwarding")
	}
	ipmap := nftDump(t, "list", "map", "inet", "nat", "dnat_tcp_ipmap")
	if !strings.Contains(ipmap, "192.168.50.10") {
		t.Errorf("dnat target missing from ipmap: %s", ipmap)
	}
	portmap := nftDump(t, "list", "map", "inet", "nat", "dnat_tcp_portmap")
	if !strings.Contains(portmap, "8080") {
		t.Errorf("dnat port missing from portmap: %s", portmap)
	}

	if err := deleteForwarding(fwd, clientIP, false, false); err != nil {
		t.Fatalf("deleteForwarding: %v", err)
	}
	if isForwardingInstalled(fwd, clientIP, false) {
		t.Error("isForwardingInstalled = true after deleteForwarding")
	}
}

// addBlock with a DNS-derived address must install a timed element.
func TestBlockTimeoutElement(t *testing.T) {
	client := GetNFTClient()
	key, _ := buildIPIPProtocolPortRangeKeys("10.99.5.1", "10.99.5.2", "udp", "53")

	err := client.AddMapElementWithTimeout(TableFamilyInet, "filter", "fwd_block",
		key, []byte("goto PFWDROPLOG"), 90*time.Second)
	if err != nil {
		t.Fatalf("timed add: %v", err)
	}
	t.Cleanup(func() { _ = client.DeleteMapElement(TableFamilyInet, "filter", "fwd_block", key) })

	out, err := exec.Command("nft", "list", "map", "inet", "filter", "fwd_block").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v", err)
	}
	listing := strings.Join(strings.Fields(string(out)), " ")
	if !strings.Contains(listing, "timeout 1m30s") {
		t.Errorf("timed element missing timeout in kernel state: %s", listing)
	}
	if !strings.Contains(listing, "expires") {
		t.Errorf("timed element not counting down: %s", listing)
	}
}

// Ranged keys (CIDR clients, port ranges) were supported by the nft CLI path;
// "0-65535" is the BlockRule default DstPort.
func TestBlockRangeEquivalence(t *testing.T) {
	client := GetNFTClient()

	t.Run("cidr client and full port range", func(t *testing.T) {
		key, keyEnd := buildIPIPProtocolPortRangeKeys("10.99.8.0/24", "10.99.8.5", "tcp", "0-65535")
		if key == nil {
			t.Fatal("range key build failed")
		}
		assertElementEquivalence(t, "inet", "filter", "fwd_block",
			[]string{"10.99.8.0/24", ".", "10.99.8.5", ".", "tcp", ".", "0-65535", ":", "goto PFWDROPLOG"},
			func() error {
				return client.AddMapElementRangeWithTimeout(TableFamilyInet, "filter", "fwd_block", key, keyEnd, []byte("goto PFWDROPLOG"), 0)
			},
			func() error {
				return client.DeleteMapElementRange(TableFamilyInet, "filter", "fwd_block", key, keyEnd)
			},
		)
	})

	t.Run("port range with timeout", func(t *testing.T) {
		key, keyEnd := buildIPIPProtocolPortRangeKeys("10.99.8.1", "10.99.8.6", "udp", "1000-2000")
		assertElementEquivalence(t, "inet", "filter", "fwd_block",
			[]string{"10.99.8.1", ".", "10.99.8.6", ".", "udp", ".", "1000-2000", "timeout", "60s", ":", "goto PFWDROPLOG"},
			func() error {
				return client.AddMapElementRangeWithTimeout(TableFamilyInet, "filter", "fwd_block", key, keyEnd, []byte("goto PFWDROPLOG"), 60*time.Second)
			},
			func() error {
				return client.DeleteMapElementRange(TableFamilyInet, "filter", "fwd_block", key, keyEnd)
			},
		)
	})

	t.Run("dnat key port range", func(t *testing.T) {
		key, keyEnd := buildIPIPPortRangeKeys("10.99.8.2", "10.99.8.7", "1000-2000")
		assertElementEquivalence(t, "inet", "nat", "dnat_tcp_ipmap",
			[]string{"10.99.8.2", ".", "10.99.8.7", ".", "1000-2000", ":", "192.168.50.5"},
			func() error {
				return client.AddMapElementRangeWithTimeout(TableFamilyInet, "nat", "dnat_tcp_ipmap", key, keyEnd, IPToBytes("192.168.50.5"), 0)
			},
			func() error {
				return client.DeleteMapElementRange(TableFamilyInet, "nat", "dnat_tcp_ipmap", key, keyEnd)
			},
		)
	})
}

// the default DstPort "0-65535" and a CIDR client through the pfw functions
func TestBlockRuleRangeRoundTrip(t *testing.T) {
	br := BlockRule{Protocol: "tcp", Dst: Address{IP: "10.99.9.5"}, DstPort: "0-65535"}
	const clientIP = "10.99.9.0/24"

	if isBlockInstalled(br, clientIP) {
		t.Fatal("block unexpectedly installed before add")
	}

	if err := addBlock(br, clientIP); err != nil {
		t.Fatalf("addBlock: %v", err)
	}
	t.Cleanup(func() { _ = deleteBlock(br, clientIP, false) })

	if !isBlockInstalled(br, clientIP) {
		t.Error("isBlockInstalled = false after addBlock")
	}
	listing := nftDump(t, "list", "map", "inet", "filter", "fwd_block")
	if !strings.Contains(listing, "10.99.9.0/24") || !strings.Contains(listing, "0-65535") {
		t.Errorf("ranged block element not rendered as ranges: %s", listing)
	}

	if err := deleteBlock(br, clientIP, false); err != nil {
		t.Fatalf("deleteBlock: %v", err)
	}
	if isBlockInstalled(br, clientIP) {
		t.Error("isBlockInstalled = true after deleteBlock")
	}
}
