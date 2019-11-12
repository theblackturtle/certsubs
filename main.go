package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultTLSConnectTimeout = 1 * time.Second
	defaultHandshakeDeadline = 3 * time.Second
)

var (
	// Public & free DNS servers
	PublicResolvers = []string{
		"1.1.1.1:53",     // Cloudflare
		"8.8.8.8:53",     // Google
		"64.6.64.6:53",   // Verisign
		"77.88.8.8:53",   // Yandex.DNS
		"74.82.42.42:53", // Hurricane Electric
		"1.0.0.1:53",     // Cloudflare Secondary
		"8.8.4.4:53",     // Google Secondary
		"77.88.8.1:53",   // Yandex.DNS Secondary
		// The following servers have shown to be unreliable
		//"64.6.65.6:53",      // Verisign Secondary
		//"9.9.9.9:53",         // Quad9
		//"149.112.112.112:53", // Quad9 Secondary
		//"84.200.69.80:53",    // DNS.WATCH
		//"84.200.70.40:53",    // DNS.WATCH Secondary
		//"8.26.56.26:53",      // Comodo Secure DNS
		//"8.20.247.20:53",     // Comodo Secure DNS Secondary
		//"195.46.39.39:53",    // SafeDNS
		//"195.46.39.40:53",    // SafeDNS Secondary
		//"69.195.152.204:53",  // OpenNIC
		//"216.146.35.35:53",   // Dyn
		//"216.146.36.36:53",   // Dyn Secondary
		//"37.235.1.174:53",   // FreeDNS
		//"37.235.1.177:53",   // FreeDNS Secondary
		//"156.154.70.1:53",    // Neustar
		//"156.154.71.1:53",   // Neustar Secondary
		//"91.239.100.100:53", // UncensoredDNS
		//"89.233.43.71:53",   // UncensoredDNS Secondary
		// Thought to falsely accuse researchers of malicious activity
		// "208.67.222.222:53", // OpenDNS Home
		// "208.67.220.220:53", // OpenDNS Home Secondary
		// These DNS servers have shown to send back fake answers
		//"198.101.242.72:53", // Alternate DNS
		//"23.253.163.53:53",  // Alternate DNS Secondary
	}
)

func main() {
	connPort := *flag.String("p", "443", "Ports to connect, separate with comma.")
	threads := *flag.Int("t", 5, "Threads to use.")
	flag.Parse()
	if len(connPort) == 0 {
		fmt.Println("Please check your ports input")
		os.Exit(0)
	}

	var ports []string
	if strings.Contains(connPort, ",") {
		ports = strings.Split(connPort, ",")

	} else {
		ports = []string{connPort}
	}

	var wg sync.WaitGroup
	jobsChan := make(chan string, threads*2)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobsChan {
				certs := getCert(addr, ports)
				for _, c := range certs {
					fmt.Println(c)
				}
			}
		}()
	}

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(strings.ToLower(sc.Text()))
		jobsChan <- line
	}
	close(jobsChan)
	wg.Wait()
}

func getCert(addr string, ports []string) []string {
	var certs []string
	for _, port := range ports {
		cfg := &tls.Config{InsecureSkipVerify: true}

		// Set the maximum time allowed for making the connection
		ctx, cancel := context.WithTimeout(context.Background(), defaultTLSConnectTimeout)
		defer cancel()

		// Obtain the connection
		conn, err := dialContext(ctx, "tcp", addr+":"+port)
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer conn.Close()

		c := tls.Client(conn, cfg)

		// Attempt to acquire the certificate chain
		errChan := make(chan error, 2)
		// This goroutine will break us out of the handshake
		time.AfterFunc(defaultHandshakeDeadline, func() {
			errChan <- errors.New("Handshake timeout")
		})
		// Be sure we do not wait too long in this attempt
		c.SetDeadline(time.Now().Add(defaultHandshakeDeadline))
		// The handshake is performed in the goroutine
		go func() {
			errChan <- c.Handshake()
		}()
		// The error channel returns handshake or timeout error
		if err = <-errChan; err != nil {
			continue
		}
		// Get the correct certificate in the chain
		certChain := c.ConnectionState().PeerCertificates
		cert := certChain[0]
		// Create the new requests from names found within the cert
		certs = append(certs, namesFromCert(cert)...)
	}
	return certs
}

func namesFromCert(cert *x509.Certificate) []string {
	var cn string

	for _, name := range cert.Subject.Names {
		oid := name.Type
		if len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4 {
			if oid[3] == 3 {
				cn = fmt.Sprintf("%s", name.Value)
				break
			}
		}
	}

	var subdomains []string
	// Add the subject common name to the list of subdomain names
	commonName := removeAsteriskLabel(cn)
	if commonName != "" {
		subdomains = append(subdomains, commonName)
	}
	// Add the cert DNS names to the list of subdomain names
	for _, name := range cert.DNSNames {
		n := removeAsteriskLabel(name)
		if n != "" {
			subdomains = uniqAppend(subdomains, n)
		}
	}
	return subdomains
}

func removeAsteriskLabel(s string) string {
	var index int

	labels := strings.Split(s, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if strings.TrimSpace(labels[i]) == "*" {
			break
		}
		index = i
	}
	if index == len(labels)-1 {
		return ""
	}
	return strings.Join(labels[index:], ".")
}

func dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     DNSDialContext,
		},
	}
	return d.DialContext(ctx, network, address)
}
func DNSDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{}

	return d.DialContext(ctx, network, nextResolverAddress())
}

// NextResolverAddress - Requests the next server
func nextResolverAddress() string {
	resolvers := PublicResolvers
	rnd := rand.Int()
	idx := rnd % len(resolvers)
	return resolvers[idx]
}

func uniqAppend(orig []string, add ...string) []string {
	return append(orig, newUniqueElements(orig, add...)...)
}

// NewUniqueElements - Removes elements that have duplicates in the original or new elements
func newUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		// Check the original slice for duplicates
		for _, ov := range orig {
			if s == strings.ToLower(ov) {
				found = true
				break
			}
		}
		// Check that we didn't already add it in
		if !found {
			for _, nv := range n {
				if s == nv {
					found = true
					break
				}
			}
		}
		// If no duplicates were found, add the entry in
		if !found {
			n = append(n, s)
		}
	}
	return n
}
