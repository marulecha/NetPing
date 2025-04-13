package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
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
	maxRetries      = 3                     // Number of retries for each host
	concurrentLimit = 100                   // Maximum number of concurrent goroutines
	icmpTimeout     = 2 * time.Second       // Timeout for ICMP requests
	rateLimit       = 10 * time.Millisecond // 100 requests per second
)

func main() {

	//logo
	fmt.Println(" ▐ ▄ ▄▄▄ .▄▄▄▄▄ ▄▄▄·▪   ▐ ▄  ▄▄ • \n•█▌▐█▀▄.▀·•██  ▐█ ▄███ •█▌▐█▐█ ▀ ▪\n▐█▐▐▌▐▀▀▪▄ ▐█.▪ ██▀·▐█·▐█▐▐▌▄█ ▀█▄\n██▐█▌▐█▄▄▌ ▐█▌·▐█▪·•▐█▌██▐█▌▐█▄▪▐█\n▀▀ █▪ ▀▀▀  ▀▀▀ .▀   ▀▀▀▀▀ █▪·▀▀▀▀ ")
	// Define input flags
	targetFilePtr := flag.String("target-file", "", "Specify a file containing a list of IP addresses, networks, or domains (one per line)")
	outputFilePtr := flag.String("output-file", "alive-hosts.txt", "Specify the output file to save alive hosts")
	verbosePtr := flag.Bool("verbose", false, "Enable verbose output to print results to the console")
	flag.Parse()

	if *targetFilePtr == "" {
		log.Fatal("Error: -target-file flag is required")
	}

	// Open the target file
	file, err := os.Open(*targetFilePtr)
	if err != nil {
		log.Fatalf("Error opening file '%s': %v\n", *targetFilePtr, err)
	}
	defer file.Close()

	// Open the output file for writing
	outputFile, err := os.Create(*outputFilePtr)
	if err != nil {
		log.Fatalf("Error creating output file '%s': %v\n", *outputFilePtr, err)
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

	// Rate limiter
	rateLimiter := time.Tick(rateLimit)

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
		} else if net.ParseIP(line) != nil || isDomain(line) {
			// Count single IP or domain
			totalHosts++
		}
	}

	// Reset the file scanner to read the file again
	file.Seek(0, 0)
	scanner = bufio.NewScanner(file)

	// Start a goroutine to periodically print progress if verbose is disabled
	if !*verbosePtr {
		go func() {
			var lastProgress int32
			for {
				time.Sleep(500 * time.Millisecond)
				currentProgress := atomic.LoadInt32(&progressCount)
				if currentProgress != lastProgress {
					fmt.Printf("\rPinging: %d/%d hosts", currentProgress, totalHosts)
					lastProgress = currentProgress
				}
			}
		}()
	}

	// Read the file line by line and process each host
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Check if the line is a valid IP, CIDR range, or domain
		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			// Handle CIDR range
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				wg.Add(1)
				sem <- struct{}{} // Acquire a semaphore slot
				<-rateLimiter     // Rate limiting
				go func(ip string) {
					defer wg.Done()
					defer func() { <-sem }() // Release the semaphore slot
					pingHost(ip, *verbosePtr, &aliveCount, &notAliveCount, &progressCount, outputWriter)
				}(ip.String())
			}
		} else if net.ParseIP(line) != nil {
			// Handle single IP
			wg.Add(1)
			sem <- struct{}{} // Acquire a semaphore slot
			<-rateLimiter     // Rate limiting
			go func(ip string) {
				defer wg.Done()
				defer func() { <-sem }() // Release the semaphore slot
				pingHost(ip, *verbosePtr, &aliveCount, &notAliveCount, &progressCount, outputWriter)
			}(line)
		} else if isDomain(line) {
			// Handle domain
			wg.Add(1)
			sem <- struct{}{} // Acquire a semaphore slot
			<-rateLimiter     // Rate limiting
			go func(domain string) {
				defer wg.Done()
				defer func() { <-sem }() // Release the semaphore slot
				ip := resolveDomain(domain)
				if ip != "" {
					pingHost(ip, *verbosePtr, &aliveCount, &notAliveCount, &progressCount, outputWriter)
				} else {
					atomic.AddInt32(&notAliveCount, 1)
					atomic.AddInt32(&progressCount, 1)
				}
			}(line)
		} else {
			log.Printf("Invalid IP, CIDR range, or domain: %s\n", line)
		}
	}

	// Check for errors while reading the file
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file '%s': %v\n", *targetFilePtr, err)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Flush the output writer
	outputWriter.Flush()

	// Print the results
	fmt.Printf("\nPing scan completed.\n")
	fmt.Printf("Alive hosts: %d\n", aliveCount)
	fmt.Printf("Offline hosts: %d\n", notAliveCount)
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
		log.Printf("Error creating ICMP connection: %v\n", err)
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
		log.Printf("Error marshaling ICMP message: %v\n", err)
		return false
	}

	// Send ICMP request
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		log.Printf("Invalid target IP: %s\n", target)
		return false
	}
	if _, err := conn.WriteTo(msgBytes, &net.IPAddr{IP: targetIP}); err != nil {
		log.Printf("Error sending ICMP request to %s: %v\n", target, err)
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

// Check if a string is a domain
func isDomain(host string) bool {
	return net.ParseIP(host) == nil && strings.Contains(host, ".")
}

// Resolve a domain to its IP address
func resolveDomain(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Printf("Failed to resolve domain %s: %v\n", domain, err)
		return ""
	}
	for _, ip := range ips {
		if ip.To4() != nil { // Return the first IPv4 address
			return ip.String()
		}
	}
	return ""
}

// Ping a host and handle results
func pingHost(ip string, verbose bool, aliveCount, notAliveCount, progressCount *int32, writer *bufio.Writer) {
	if isHostAliveWithRetries(ip) {
		atomic.AddInt32(aliveCount, 1)
		if verbose {
			fmt.Printf("Host %s is alive\n", ip)
		}
		saveToFile(writer, ip)
	} else {
		atomic.AddInt32(notAliveCount, 1)
		if verbose {
			fmt.Printf("Host %s is not alive\n", ip)
		}
	}
	atomic.AddInt32(progressCount, 1)
}
