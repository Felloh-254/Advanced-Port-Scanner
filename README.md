# Advanced Port Scanner

## Overview

Advanced Port Scanner is a high-performance, concurrent network scanning tool written in Go. It is designed for real-world use cases such as network diagnostics, service discovery, and entry-level security assessments.

Unlike basic scanners that only tell you whether a port is open or closed, this tool goes several steps further. It attempts to understand *what is actually running* behind each open port and provides contextual insights that can help in troubleshooting, auditing, or security testing.

It combines speed (through concurrency) with intelligence (through service detection, HTTP inspection, and TLS analysis), making it a practical tool for developers, system administrators, and cybersecurity learners.

---

## Key Capabilities

### 1. High-Speed Concurrent Scanning

The scanner uses Go's goroutines and worker pools to perform multiple port scans in parallel. This drastically reduces scan time compared to sequential approaches.

### 2. Service Detection & Version Fingerprinting

Instead of just reporting open ports, the tool attempts to grab banners and identify:

* Service type (e.g., SSH, HTTP, Redis)
* Version information (where available)

This helps you understand *what software is exposed* on your system.

### 3. HTTP / HTTPS Inspection

For web services, the scanner performs deeper analysis:

* HTTP status codes (e.g., 200, 403)
* Page titles (useful for identifying apps)
* Response headers

This is particularly useful for quickly identifying misconfigured or exposed web services.

### 4. TLS / SSL Analysis

When scanning HTTPS services, the tool extracts:

* Certificate details
* Cipher suite information

This can help identify weak encryption configurations or expired certificates.

### 5. Basic Vulnerability Awareness

The scanner includes a lightweight vulnerability detection layer:

* Flags commonly insecure services (e.g., Telnet, exposed Redis)
* Associates known CVEs with detected services
* Provides suggestions in verbose mode

Note: This is not a full vulnerability scanner, but a quick awareness layer.

### 6. Flexible Port Targeting

Supports:

* Single ports
* Comma-separated lists (e.g., 80,443,8080)
* Port ranges (e.g., 8000-9000)

### 7. Rate Limiting

Control how aggressive the scan is by limiting requests per second. Useful when scanning production systems or avoiding detection.

### 8. Structured Output

Outputs can be generated in:

* Human-readable console format
* JSON format for automation and integrations

### 9. Verbose Mode

When enabled, the scanner provides:

* More detailed scan results
* Contextual explanations
* Basic remediation suggestions

---

## Architecture

The scanner is built using a modular and scalable design:

* **Config Layer**: Parses CLI flags and initializes runtime configuration
* **Scanner Engine**: Coordinates the scanning process
* **Worker Pool**: Handles concurrency and distributes scanning jobs
* **Service Detection Module**: Performs banner grabbing and service identification
* **Protocol Handlers**: Specialized handlers for HTTP and HTTPS analysis
* **Output Engine**: Formats results for console or JSON output

This structure makes the tool easier to extend and maintain.

---

## Installation

### Requirements

* Go 1.20 or higher

### Build Instructions

```bash
git clone <repository-url>
cd advanced-port-scanner
go build -o scanner scanner.go
```

---

## Usage

### Basic Usage

```bash
./scanner -target <host>
```

### Command-Line Options

| Flag     | Description                                 |
| -------- | ------------------------------------------- |
| -target  | Target host (IP address or domain)          |
| -ports   | Port list or range (e.g., 80,443,8000-8090) |
| -start   | Start port (default: 1)                     |
| -end     | End port (default: 1024)                    |
| -threads | Number of concurrent workers                |
| -timeout | Connection timeout                          |
| -output  | Output file                                 |
| -json    | Enable JSON output                          |
| -verbose | Enable detailed output                      |
| -service | Enable service version detection            |
| -os      | Enable OS detection (heuristic)             |
| -rate    | Rate limit (requests per second)            |
| -retries | Retry attempts for failed scans             |
| -mode    | Scan mode (tcp or syn)                      |

---

## Example Commands

### Basic Scan

```bash
./scanner -target scanme.nmap.org
```

### Custom Port Selection

```bash
./scanner -target example.com -ports 80,443,8080-8090
```

### Full Range Scan with OS Detection

```bash
./scanner -target 192.168.1.1 -start 1 -end 65535 -os -verbose
```

### JSON Output

```bash
./scanner -target localhost -json -output report.json
```

---

## Sample Output

### Console Output

```
[✓] Port 22 OPEN (SSH v8.2) (15.32ms)
[✓] Port 80 OPEN (HTTP) - Welcome Page [HTTP 200] (22.11ms)
[✓] Port 443 OPEN (HTTPS) - Secure Site (18.45ms)
[✓] Port 6379 OPEN (Redis) VULNERABLE (CVE-2022-0543) (5.12ms)
```

### JSON Output

```json
{
  "target": "example.com",
  "open_ports": [22, 80, 443],
  "results": [
    {
      "port": 80,
      "service": "HTTP",
      "status_code": 200,
      "title": "Welcome Page"
    }
  ]
}
```

---

## Security Insights

The tool provides quick, actionable insights:

* Identifies potentially dangerous exposed services
* Maps services to known vulnerabilities (CVE references)
* Suggests basic remediation steps in verbose mode

This makes it useful for quick audits and learning environments.

---

## Known Limitations

* SYN scanning is not fully implemented (requires raw socket access)
* OS detection is heuristic and may not be accurate
* Banner grabbing depends on service responsiveness
* Not a replacement for advanced tools like Nmap

---

## Legal Disclaimer

This tool is intended for educational purposes and authorized testing only.

Unauthorized scanning of networks or systems without permission may be illegal. Always ensure you have proper authorization before running scans.

---

## Roadmap

Planned improvements include:

* Full SYN scan implementation
* UDP scanning support
* Plugin-based architecture for service detection
* Improved OS fingerprinting
* Integration with SIEM tools
* Enhanced CLI output (tables, colorization)

---

## Contributing

Contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with clear documentation

---

## License

This project is licensed under the MIT License.

---

## Author

Developed as part of a hands-on exploration of Go, concurrency, and network security tooling.

It reflects practical implementation of concepts like worker pools, rate limiting, and protocol analysis.
