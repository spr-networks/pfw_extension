//go:build darwin

package main

import (
	"fmt"
	"time"
)

// Stubs so pfw compiles on macOS for development; nftables operations are
// linux-only and the production build runs in a Linux container.

type TableFamily uint32

const (
	TableFamilyInet TableFamily = 1
	TableFamilyIP   TableFamily = 2
)

type NFTClient struct{}

var errNotSupported = fmt.Errorf("nftables not supported on macOS")

func InitNFTClient() {}

func GetNFTClient() *NFTClient {
	return &NFTClient{}
}

func (c *NFTClient) GetMapElement(family TableFamily, tableName, mapName string, key []byte) error {
	return errNotSupported
}

func (c *NFTClient) AddMapElementWithTimeout(family TableFamily, tableName, mapName string, key, value []byte, timeout time.Duration) error {
	return errNotSupported
}

func (c *NFTClient) DeleteMapElement(family TableFamily, tableName, mapName string, key []byte) error {
	return errNotSupported
}

func buildIPIPKey(srcIP, dstIP string) []byte {
	return nil
}

func buildIPIPPortKey(srcIP, dstIP, port string) []byte {
	return nil
}

func buildIPIPProtocolPortRangeKeys(srcIP, dstIP, protocol, port string) (key, keyEnd []byte) {
	return nil, nil
}

func buildIPIPRangeKeys(srcIP, dstIP string) (key, keyEnd []byte) {
	return nil, nil
}

func buildIPIPPortRangeKeys(srcIP, dstIP, port string) (key, keyEnd []byte) {
	return nil, nil
}

func buildIPIPIfaceRangeKeys(srcIP, dstIP, iface string) (key, keyEnd []byte) {
	return nil, nil
}

func buildIPIPPortIfaceRangeKeys(srcIP, dstIP, port, iface string) (key, keyEnd []byte) {
	return nil, nil
}

func (c *NFTClient) AddMapElementRangeWithTimeout(family TableFamily, tableName, mapName string, key, keyEnd, value []byte, timeout time.Duration) error {
	return errNotSupported
}

func (c *NFTClient) DeleteMapElementRange(family TableFamily, tableName, mapName string, key, keyEnd []byte) error {
	return errNotSupported
}

func IPToBytes(ip string) []byte {
	return nil
}

func PortToBytes(port string) []byte {
	return nil
}

func CheckChainExists(family, tableName, chainName string) error {
	return errNotSupported
}

func AddChain(family, tableName, chainName string) error {
	return errNotSupported
}

func DeleteChain(family, tableName, chainName string) error {
	return errNotSupported
}

func AddMarkSetRule(family, tableName, chainName string, mark uint32) error {
	return errNotSupported
}

func AddAcceptRule(family, tableName, chainName string) error {
	return errNotSupported
}

func FlushSetWithTable(family, table, setName string) error {
	return errNotSupported
}

func AddInterfaceToSet(setName, iface string) error {
	return errNotSupported
}

func FlushMapByName(family, tableName, mapName string) error {
	return errNotSupported
}

func AddDstSupernetworksAcceptRule(family, tableName, chainName string) error {
	return errNotSupported
}
