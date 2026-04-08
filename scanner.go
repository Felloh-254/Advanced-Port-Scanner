package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ================= CONFIG =================

type Config struct {
	Target      string
	StartPort   int
	EndPort     int
	Concurrency int
	Timeout     time.Duration
	OutputFile  string
	ScanMode    string // "tcp", "syn", "udp"
	Verbose     bool
	ServiceScan bool   // Deep service detection
	OSDetection bool   // OS fingerprinting
	NoPing      bool   // Don't ping before scan
	Ports       string // Port specification (e.g., "80,443,8080-8090")
	JSONOutput  bool
	RateLimit   int // Packets per second
	Retries     int
}

// ================= ENHANCED SERVICES DB =================

type ServiceInfo struct {
	Name        string
	Version     string
	OS          string
	Vulnerable  bool
	CVE         string
	Suggestions []string
}

var serviceDB = map[int]ServiceInfo{
	21:    {Name: "FTP", Vulnerable: false, Suggestions: []string{"Disable anonymous login", "Use SFTP instead"}},
	22:    {Name: "SSH", Vulnerable: false, Suggestions: []string{"Disable root login", "Use key-based auth"}},
	23:    {Name: "Telnet", Vulnerable: true, CVE: "CVE-2020-10188", Suggestions: []string{"USE SSH INSTEAD - Telnet is insecure!"}},
	25:    {Name: "SMTP", Vulnerable: false, Suggestions: []string{"Enable TLS", "Configure SPF/DKIM/DMARC"}},
	80:    {Name: "HTTP", Vulnerable: false, Suggestions: []string{"Use HTTPS", "Implement security headers"}},
	443:   {Name: "HTTPS", Vulnerable: false, Suggestions: []string{"Check SSL/TLS configuration", "Use modern ciphers"}},
	3306:  {Name: "MySQL", Vulnerable: false, Suggestions: []string{"Remove default users", "Use strong passwords"}},
	6379:  {Name: "Redis", Vulnerable: true, CVE: "CVE-2022-0543", Suggestions: []string{"Add authentication", "Bind to localhost"}},
	27017: {Name: "MongoDB", Vulnerable: true, CVE: "CVE-2019-10758", Suggestions: []string{"Enable authentication", "Use --bind_ip"}},
}

// ================= RESULT (Enhanced) =================

type ScanResult struct {
	Port         int
	Service      string
	Version      string
	Banner       string
	Title        string
	StatusCode   int
	ResponseTime time.Duration
	OS           string
	Vulnerable   bool
	CVE          string
	Suggestions  []string
	Metadata     map[string]interface{}
}

// ================= ADVANCED SCANNER =================

type AdvancedScanner struct {
	cfg         Config
	openPorts   []int
	results     []ScanResult
	stats       ScanStats
	rateLimiter *time.Ticker
	synSequence uint32
}

type ScanStats struct {
	TotalPorts int32
	Scanned    int32
	Open       int32
	Closed     int32
	Filtered   int32
	StartTime  time.Time
	EndTime    time.Time
}

// TCP Connect Scan (Enhanced)
func (s *AdvancedScanner) scanPort(port int) *ScanResult {
	address := net.JoinHostPort(s.cfg.Target, fmt.Sprintf("%d", port))
	start := time.Now()

	conn, err := net.DialTimeout("tcp", address, s.cfg.Timeout)
	if err != nil {
		atomic.AddInt32(&s.stats.Closed, 1)
		return nil
	}
	defer conn.Close()

	responseTime := time.Since(start)
	atomic.AddInt32(&s.stats.Open, 1)

	result := &ScanResult{
		Port:         port,
		Service:      detectService(port),
		ResponseTime: responseTime,
		Metadata:     make(map[string]interface{}),
	}

	// Service version detection (enhanced)
	if s.cfg.ServiceScan {
		s.detectServiceVersion(conn, result)
	}

	// HTTP/HTTPS specific checks
	switch port {
	case 80, 8080, 8000:
		s.grabHTTPInfo(result)
	case 443, 8443:
		s.grabHTTPSInfo(result)
	}

	// Vulnerability check
	if info, exists := serviceDB[port]; exists {
		result.Vulnerable = info.Vulnerable
		result.CVE = info.CVE
		result.Suggestions = info.Suggestions
	}

	// OS Detection
	if s.cfg.OSDetection && result.Banner != "" {
		result.OS = s.detectOSFromBanner(result.Banner)
	}

	return result
}

// Service version detection using banner grabbing
func (s *AdvancedScanner) detectServiceVersion(conn net.Conn, result *ScanResult) {
	// Send common probes based on service
	probes := map[int]string{
		21:  "USER anonymous\r\n",
		22:  "SSH-2.0-Client\r\n",
		25:  "EHLO test\r\n",
		80:  "HEAD / HTTP/1.0\r\n\r\n",
		443: "HEAD / HTTP/1.0\r\n\r\n",
	}

	if probe, exists := probes[result.Port]; exists {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte(probe))
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		banner := string(buffer[:n])
		result.Banner = strings.TrimSpace(banner)

		// Extract version numbers using regex
		versionRe := regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?`)
		if version := versionRe.FindString(banner); version != "" {
			result.Version = version
		}
	}
}

// HTTP Info grabbing (enhanced with status codes)
func (s *AdvancedScanner) grabHTTPInfo(result *ScanResult) {
	client := &http.Client{
		Timeout: s.cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	url := fmt.Sprintf("http://%s:%d", s.cfg.Target, result.Port)
	resp, err := client.Get(url)
	if err == nil {
		defer resp.Body.Close()
		result.StatusCode = resp.StatusCode

		// Get title
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(strings.ToLower(line), "<title>") {
				re := regexp.MustCompile(`<title>(.*?)</title>`)
				matches := re.FindStringSubmatch(line)
				if len(matches) > 1 {
					result.Title = matches[1]
					break
				}
			}
		}

		// Security headers check
		headers := resp.Header
		if headers.Get("X-Frame-Options") == "" {
			result.Suggestions = append(result.Suggestions, "Missing X-Frame-Options header")
		}
		if headers.Get("X-Content-Type-Options") == "" {
			result.Suggestions = append(result.Suggestions, "Missing X-Content-Type-Options header")
		}
	}
}

// HTTPS Info grabbing (TLS details)
func (s *AdvancedScanner) grabHTTPSInfo(result *ScanResult) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: s.cfg.Timeout},
		"tcp", fmt.Sprintf("%s:%d", s.cfg.Target, result.Port), conf)
	if err == nil {
		defer conn.Close()

		state := conn.ConnectionState()
		cert := state.PeerCertificates[0]

		result.Metadata["TLS_Version"] = tlsVersionToString(state.Version)
		result.Metadata["Cipher_Suite"] = tls.CipherSuiteName(state.CipherSuite)
		result.Metadata["Certificate_Issuer"] = cert.Issuer.CommonName
		result.Metadata["Certificate_Expiry"] = cert.NotAfter

		if time.Now().After(cert.NotAfter) {
			result.Suggestions = append(result.Suggestions, "SSL Certificate expired!")
		}

		// Also get HTTP title via HTTPS
		s.grabHTTPInfo(result)
	}
}

// OS Detection from banner
func (s *AdvancedScanner) detectOSFromBanner(banner string) string {
	bannerLower := strings.ToLower(banner)

	switch {
	case strings.Contains(bannerLower, "windows"):
		return "Windows"
	case strings.Contains(bannerLower, "linux"):
		return "Linux"
	case strings.Contains(bannerLower, "ubuntu"):
		return "Ubuntu"
	case strings.Contains(bannerLower, "debian"):
		return "Debian"
	case strings.Contains(bannerLower, "centos"):
		return "CentOS"
	case strings.Contains(bannerLower, "freebsd"):
		return "FreeBSD"
	default:
		return "Unknown"
	}
}

// SYN Scan simulation (requires raw sockets - root/admin)
func (s *AdvancedScanner) synScan() bool {
	// This is a simplified version - real SYN scan requires raw sockets
	// For production, use libraries like `github.com/google/gopacket`
	fmt.Println("SYN scan requires raw socket access (run as root)")
	return false
}

// ================= ENHANCED WORKER POOL =================

func (s *AdvancedScanner) Run() {
	s.stats.StartTime = time.Now()

	ports := make(chan int, s.cfg.Concurrency)
	results := make(chan *ScanResult, s.cfg.Concurrency)
	var wg sync.WaitGroup

	// Rate limiting if specified
	if s.cfg.RateLimit > 0 {
		s.rateLimiter = time.NewTicker(time.Second / time.Duration(s.cfg.RateLimit))
		defer s.rateLimiter.Stop()
	}

	// Start workers
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go s.worker(ports, results, &wg)
	}

	// Send ports to scan
	go func() {
		portsList := s.parsePorts()
		for _, port := range portsList {
			if s.rateLimiter != nil {
				<-s.rateLimiter.C
			}
			ports <- port
			atomic.AddInt32(&s.stats.Scanned, 1)
		}
		close(ports)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		s.results = append(s.results, *result)
		s.openPorts = append(s.openPorts, result.Port)
		s.printResult(result)
	}

	s.stats.EndTime = time.Now()
}

func (s *AdvancedScanner) worker(ports <-chan int, results chan<- *ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for port := range ports {
		var result *ScanResult

		switch s.cfg.ScanMode {
		case "syn":
			if s.synScan() {
				result = &ScanResult{Port: port, Service: detectService(port)}
			}
		default: // tcp connect scan
			result = s.scanPort(port)
		}

		if result != nil {
			results <- result
		}
	}
}

// ================= UTILITIES =================

func (s *AdvancedScanner) parsePorts() []int {
	var ports []int

	if s.cfg.Ports != "" {
		// Parse custom port specification
		parts := strings.Split(s.cfg.Ports, ",")
		for _, part := range parts {
			if strings.Contains(part, "-") {
				// Range like "80-100"
				rangeParts := strings.Split(part, "-")
				start, end := parseInt(rangeParts[0]), parseInt(rangeParts[1])
				for p := start; p <= end; p++ {
					ports = append(ports, p)
				}
			} else {
				// Single port
				ports = append(ports, parseInt(part))
			}
		}
	} else {
		// Use start/end range
		for p := s.cfg.StartPort; p <= s.cfg.EndPort; p++ {
			ports = append(ports, p)
		}
	}

	return ports
}

func (s *AdvancedScanner) printResult(res *ScanResult) {
	if !s.cfg.Verbose && res == nil {
		return
	}

	fmt.Printf("[✓] Port %d OPEN", res.Port)

	if res.Service != "unknown" {
		fmt.Printf(" (%s", res.Service)
		if res.Version != "" {
			fmt.Printf(" v%s", res.Version)
		}
		fmt.Printf(")")
	}

	if res.Title != "" {
		fmt.Printf(" - %s", res.Title)
	}

	if res.StatusCode > 0 {
		fmt.Printf(" [HTTP %d]", res.StatusCode)
	}

	if res.Vulnerable {
		fmt.Printf(" VULNERABLE (%s)", res.CVE)
	}

	fmt.Printf(" (%.2fms)\n", float64(res.ResponseTime.Microseconds())/1000)

	if s.cfg.Verbose && len(res.Suggestions) > 0 {
		for _, suggestion := range res.Suggestions {
			fmt.Printf("   Suggestion: %s\n", suggestion)
		}
	}
}

// ================= OUTPUT FORMATS =================

func (s *AdvancedScanner) SaveResults() error {
	file, err := os.Create(s.cfg.OutputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	if s.cfg.JSONOutput {
		return s.saveJSON(file)
	}
	return s.saveText(file)
}

func (s *AdvancedScanner) saveJSON(file *os.File) error {
	output := struct {
		Target    string       `json:"target"`
		Stats     ScanStats    `json:"stats"`
		OpenPorts []int        `json:"open_ports"`
		Results   []ScanResult `json:"results"`
	}{
		Target:    s.cfg.Target,
		Stats:     s.stats,
		OpenPorts: s.openPorts,
		Results:   s.results,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func (s *AdvancedScanner) saveText(file *os.File) error {
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	fmt.Fprintf(writer, "Port Scan Report\n")
	fmt.Fprintf(writer, "================\n")
	fmt.Fprintf(writer, "Target: %s\n", s.cfg.Target)
	fmt.Fprintf(writer, "Scan Duration: %v\n", s.stats.EndTime.Sub(s.stats.StartTime))
	fmt.Fprintf(writer, "Open Ports Found: %d/%d\n\n", len(s.openPorts), s.stats.Scanned)

	// Write results
	for _, res := range s.results {
		fmt.Fprintf(writer, "Port %d: %s", res.Port, res.Service)
		if res.Version != "" {
			fmt.Fprintf(writer, " (%s)", res.Version)
		}
		if res.Title != "" {
			fmt.Fprintf(writer, " - %s", res.Title)
		}
		if res.Vulnerable {
			fmt.Fprintf(writer, " [VULNERABLE: %s]", res.CVE)
		}
		fmt.Fprintf(writer, "\n")
	}

	return nil
}

// ================= HELPER FUNCTIONS =================

func detectService(port int) string {
	if info, exists := serviceDB[port]; exists {
		return info.Name
	}
	return "unknown"
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

// ================= MAIN =================

func main() {
	cfg := Config{}

	// Basic flags
	flag.StringVar(&cfg.Target, "target", "", "Target host (IP or domain)")
	flag.StringVar(&cfg.Ports, "ports", "", "Ports to scan (e.g., '80,443,8000-9000')")
	flag.IntVar(&cfg.StartPort, "start", 1, "Start port (if -ports not used)")
	flag.IntVar(&cfg.EndPort, "end", 1024, "End port (if -ports not used)")
	flag.IntVar(&cfg.Concurrency, "threads", 100, "Number of concurrent workers")
	flag.DurationVar(&cfg.Timeout, "timeout", 2*time.Second, "Connection timeout")
	flag.StringVar(&cfg.OutputFile, "output", "scan_results.txt", "Output file")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&cfg.ServiceScan, "service", true, "Enable service version detection")
	flag.BoolVar(&cfg.OSDetection, "os", false, "Enable OS detection")
	flag.BoolVar(&cfg.JSONOutput, "json", false, "Output in JSON format")
	flag.IntVar(&cfg.RateLimit, "rate", 0, "Rate limit (packets per second, 0=unlimited)")
	flag.IntVar(&cfg.Retries, "retries", 1, "Number of retries for closed ports")
	flag.StringVar(&cfg.ScanMode, "mode", "tcp", "Scan mode (tcp/syn)")

	flag.Parse()

	if cfg.Target == "" {
		fmt.Println("Usage: go run scanner.go -target <host> [options]")
		fmt.Println("\nExamples:")
		fmt.Println("  Basic scan: go run scanner.go -target scanme.nmap.org")
		fmt.Println("  Custom ports: go run scanner.go -target example.com -ports 80,443,8080-8090")
		fmt.Println("  Full scan with OS detection: go run scanner.go -target 192.168.1.1 -start 1 -end 65535 -os -verbose")
		fmt.Println("  JSON output: go run scanner.go -target localhost -json -output report.json")
		return
	}

	scanner := &AdvancedScanner{cfg: cfg}

	fmt.Printf("\nAdvanced Port Scanner\n")
	fmt.Printf("=======================\n")
	fmt.Printf("Target: %s\n", cfg.Target)
	fmt.Printf("Scan Mode: %s\n", strings.ToUpper(cfg.ScanMode))
	fmt.Printf("Concurrency: %d\n", cfg.Concurrency)
	fmt.Printf("Timeout: %v\n", cfg.Timeout)
	fmt.Printf("Service Detection: %v\n", cfg.ServiceScan)
	fmt.Printf("OS Detection: %v\n\n", cfg.OSDetection)

	scanner.Run()

	if err := scanner.SaveResults(); err != nil {
		fmt.Printf("Error saving results: %v\n", err)
	} else {
		fmt.Printf("\n✓ Results saved to %s\n", cfg.OutputFile)
	}

	// Print summary
	fmt.Printf("\nScan Summary:\n")
	fmt.Printf("   Total ports scanned: %d\n", scanner.stats.Scanned)
	fmt.Printf("   Open ports found: %d\n", len(scanner.openPorts))
	fmt.Printf("   Duration: %v\n", scanner.stats.EndTime.Sub(scanner.stats.StartTime))

	// Security summary
	vulnerableCount := 0
	for _, res := range scanner.results {
		if res.Vulnerable {
			vulnerableCount++
		}
	}
	if vulnerableCount > 0 {
		fmt.Printf("\nWARNING: Found %d potentially vulnerable services!\n", vulnerableCount)
		fmt.Printf("   Run with -verbose for remediation suggestions\n")
	}
}
