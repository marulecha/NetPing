package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	maxRetries      = 3               // Number of retries for each host
	concurrentLimit = 100             // Maximum number of concurrent goroutines
	icmpTimeout     = 2 * time.Second // Timeout for ICMP requests
)

func main() {
	// Define input flags
	targetFilePtr := flag.String("target-file", "", "Specify a file containing a list of IP addresses or networks (one per line)")
	outputFilePtr := flag.String("output-file", "alive-hosts.txt", "Specify the output file to save alive hosts")
	verbosePtr := flag.Bool("verbose", false, "Enable verbose output to print results to the console")
	flag.Parse()

	if *targetFilePtr == "" {
		fmt.Println("Error: -target-file flag is required")
		return
	}

	// Open the target file
	file, err := os.Open(*targetFilePtr)
	if err != nil {
		fmt.Printf("Error opening file '%s': %v\n", *targetFilePtr, err)
		return
	}
	defer file.Close()

	// Open the output file for writing
	outputFile, err := os.Create(*outputFilePtr)
	if err != nil {
		fmt.Printf("Error creating output file '%s': %v\n", *outputFilePtr, err)
		return
	}
	defer outputFile.Close()
	outputWriter := bufio.NewWriter(outputFile)

	// Use a WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Use atomic counters for alive and not alive hosts
	var aliveCount int32
	var notAliveCount int32
	var progressCount int32 // Counter for progress tracking
	var totalHosts int32    // Total number of hosts to be scanned

	// Use a semaphore to limit the number of concurrent goroutines
	sem := make(chan struct{}, concurrentLimit)

	// Calculate the total number of hosts
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			// Count all IPs in the CIDR range
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				totalHosts++
			}
		} else if net.ParseIP(line) != nil {
			// Count single IP
			totalHosts++
		}
	}

	// Reset the file scanner to read the file again
	file.Seek(0, 0)
	scanner = bufio.NewScanner(file)

	// Start a goroutine to periodically print progress if verbose is disabled
	if !*verbosePtr {
		go func() {
			for {
				time.Sleep(1 * time.Second)
				currentProgress := atomic.LoadInt32(&progressCount)
				fmt.Printf("\rPinging: %d/%d hosts", currentProgress, totalHosts)
			}
		}()
	}

	// Read the file line by line and process each host
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Check if the line is a valid IP or CIDR range
		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			// Handle CIDR range
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				wg.Add(1)
				sem <- struct{}{} // Acquire a semaphore slot
				go func(ip string) {
					defer wg.Done()
					defer func() { <-sem }() // Release the semaphore slot
					if isHostAliveWithRetries(ip) {
						atomic.AddInt32(&aliveCount, 1)
						if *verbosePtr {
							fmt.Printf("Host %s is alive\n", ip)
						}
						saveToFile(outputWriter, ip)
					} else {
						atomic.AddInt32(&notAliveCount, 1)
						if *verbosePtr {
							fmt.Printf("Host %s is not alive\n", ip)
						}
					}
					atomic.AddInt32(&progressCount, 1) // Increment progress counter
				}(ip.String())
			}
		} else if net.ParseIP(line) != nil {
			// Handle single IP address
			wg.Add(1)
			sem <- struct{}{} // Acquire a semaphore slot
			go func(ip string) {
				defer wg.Done()
				defer func() { <-sem }() // Release the semaphore slot
				if isHostAliveWithRetries(ip) {
					atomic.AddInt32(&aliveCount, 1)
					if *verbosePtr {
						fmt.Printf("Host %s is alive\n", ip)
					}
					saveToFile(outputWriter, ip)
				} else {
					atomic.AddInt32(&notAliveCount, 1)
					if *verbosePtr {
						fmt.Printf("Host %s is not alive\n", ip)
					}
				}
				atomic.AddInt32(&progressCount, 1) // Increment progress counter
			}(line)
		} else {
			fmt.Printf("Invalid IP or CIDR range: %s\n", line)
		}
	}

	// Check for errors while reading the file
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file '%s': %v\n", *targetFilePtr, err)
		return
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Flush the output writer
	outputWriter.Flush()

	// Print the results
	fmt.Printf("\nPing scan completed.\n")
	fmt.Printf("Alive hosts: %d\n", aliveCount)
	fmt.Printf("Not alive hosts: %d\n", notAliveCount)
}

// Increment an IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Check if a host is alive with retries
func isHostAliveWithRetries(target string) bool {
	for i := 0; i < maxRetries; i++ {
		if isHostAlive(target) {
			return true
		}
		time.Sleep(icmpTimeout / 2) // Wait before retrying
	}
	return false
}

// Check if a host is alive using ICMP echo request
func isHostAlive(target string) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "")
	if err != nil {
		fmt.Printf("Error creating ICMP connection: %v\n", err)
		return false
	}
	defer conn.Close()

	// Create ICMP echo request
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		fmt.Printf("Error marshaling ICMP message: %v\n", err)
		return false
	}

	// Send ICMP request
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		fmt.Printf("Invalid target IP: %s\n", target)
		return false
	}
	if _, err := conn.WriteTo(msgBytes, &net.IPAddr{IP: targetIP}); err != nil {
		fmt.Printf("Error sending ICMP request to %s: %v\n", target, err)
		return false
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(icmpTimeout))

	// Read ICMP response
	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}

	// Validate that the response is from the intended target
	peerIP, ok := peer.(*net.IPAddr)
	if !ok || !peerIP.IP.Equal(targetIP) {
		return false
	}

	// Parse ICMP response
	parsedMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
	if err != nil {
		return false
	}

	// Ensure the response is an Echo Reply and matches the request ID
	if parsedMsg.Type == ipv4.ICMPTypeEchoReply {
		echoReply, ok := parsedMsg.Body.(*icmp.Echo)
		if ok && echoReply.ID == os.Getpid()&0xffff {
			return true
		}
	}

	return false
}

// Save alive host to the output file
func saveToFile(writer *bufio.Writer, ip string) {
	writer.WriteString(ip + "\n")
}
