package main

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func tcpCheck(ip string, port string) bool {

	address := ip + ":" + port

	maxAttempts := 3

	success := false

	for i := 0; i < maxAttempts; i++ {
		// Dial the address with a timeout
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err != nil {
			fmt.Printf("Connection attempt %d failed: %v\n", i+1, err)
			continue
		}

		// Connection success!
		success = true

		// Close the connection
		conn.Close()
		break
	}
	return success
}

func pingCheck(ip string) bool {
	targetIP := net.ParseIP(ip)

	numPackets := 3

	var received int

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Println("Error creating ICMP packet conn:", err)
		return false
	}
	defer conn.Close()

	// Send 3 ICMP echo request packets
	for i := 0; i < numPackets; i++ {
		message := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID: i,
			},
		}

		data, err := message.Marshal(nil)
		if err != nil {
			fmt.Println("Error marshalling ICMP message:", err)
			continue
		}

		_, err = conn.WriteTo(data, &net.IPAddr{IP: targetIP})
		if err != nil {
			fmt.Println("Error sending ICMP packet:", err)
			continue
		}

		timeoutDuration := 1 * time.Second
		deadline := time.Now().Add(timeoutDuration)

		// Set deadline for read operation
		conn.SetReadDeadline(deadline)

		buffer := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buffer)

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					fmt.Printf("Timeout waiting for response from %s (packet %d)\n", targetIP, i)
					break
				}
				fmt.Println("Error reading ICMP message:", err)
				continue
			}

			// Parse the received bytes into an ICMP message
			receivedMessage, err := icmp.ParseMessage(1, buffer[:n])
			if err != nil {
				fmt.Println("Error parsing ICMP message:", err)
				continue
			}

			// Check if it's an echo reply from the target IP
			if receivedMessage.Type == ipv4.ICMPTypeEchoReply && receivedMessage.Body.(*icmp.Echo).ID == i && addr.String() == targetIP.String() {
				received++
				break
			} else {
				fmt.Println("Received unexpected ICMP message from", addr)
			}
		}
	}

	if received > 0 {
		return true
	}
	return false
}
