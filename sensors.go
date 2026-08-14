package osctrl 

import (
	"time"
	"sync"
	"log"
	"os"
	"strings"
	"fmt"
	"net/url"
	"net"
	"regexp"
	"net/http"
	"strconv"
	"bytes"
	"io"
	"encoding/json"
	"encoding/base64"
	"encoding/hex"
	"runtime"
	"crypto/sha256"

	"path/filepath"
	"bufio"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/shuffle/shuffle-shared"
)

type MacApp struct {
	Name          string `json:"_name"`
	Version       string `json:"version"`
	BundleVersion string `json:"bundle_version"`
	Path          string `json:"path"`
	Info string `json:"info"`
}

// Scanner manages concurrent directory scanning
type Scanner struct {
	results chan shuffle.ProjectInfo
	wg      sync.WaitGroup
	mu      sync.Mutex
	visited map[string]bool // Track visited dirs to avoid symlink loops
}

type AuditLogCollector struct {
	Config     shuffle.TelemetryConfig
	Platform   string
	LogChannel chan shuffle.AuditLogEntry
	StopChan   chan bool
	mu         sync.Mutex
}

type StreamFn func(line string)

// ========================
// Helpers
// ========================

func getInt(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		}
	}
	return 0
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func isValidSerial(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))

	if s == "" {
		return false
	}

	bad := []string{
		"to be filled",
		"default string",
		"o.e.m",
		"unknown",
	}

	for _, b := range bad {
		if strings.Contains(s, b) {
			return false
		}
	}

	return true
}

func parseInt(s string) int {
	s = strings.TrimSpace(s)
	val, err := strconv.Atoi(s)
	if err != nil {
		return 0 // default to 0 if parse fails
	}
	return val
}

// MINOR validation:
// RCECleanup sanitizes a command string to reduce attack surface
// It removes/escapes shell metacharacters and dangerous patterns
func RCECleanup(command string) string {
	if strings.HasPrefix(command, "script:") {
		return command 
	}

	// Not allowing large commands at all (for now)
	maxCommandSize := 50
	if os.Getenv("RCE_MAX_COMMAND_SIZE") != "" {
		envSize := parseInt(os.Getenv("RCE_MAX_COMMAND_SIZE"))
		if envSize > 0 {
			maxCommandSize = envSize
		}
	}

	if len(command) > maxCommandSize { 
		return ""
	}

	// Trim whitespace
	command = strings.TrimSpace(command)

	// Remove shell operators
	dangerous := []string{
		";",  // Command chaining
		"|",  // Pipes
		"&",  // Background/AND
		">",  // Redirect
		"<",  // Redirect
		"`",  // Command substitution
		"$",  // Variable expansion
		"\\", // Escape character
	}

	for _, char := range dangerous {
		command = strings.ReplaceAll(command, char, "")
	}

	// Remove control characters (0x00-0x1F except tab/newline)
	re := regexp.MustCompile(`[\x00-\x08\x0B-\x1F\x7F]`)
	command = re.ReplaceAllString(command, "")

	// Collapse multiple spaces
	command = strings.Join(strings.Fields(command), " ")

	return command
}

func HandleSensorResponseAction(hostname string, sensorDetails shuffle.SensorMode, incRequest shuffle.ExecutionRequest) {
	if len(incRequest.ExecutionId) == 0 || len(incRequest.Authorization) == 0 {
		log.Printf("[WARNING] Invalid execution request: missing execution ID or action")
		return
	}

	if sensorDetails.ResponseActions != "controlled" && sensorDetails.ResponseActions != "full" {
		return 
	}

	if incRequest.Start == "" { 
		log.Printf("[WARNING] Invalid execution request: missing start ID for action reference")
		return
	}

	// From Orborus
	backendUrl := os.Getenv("BASE_URL")
	if backendUrl == "" {
		log.Printf("[ERROR] BASE_URL environment variable not set. Cannot execute response action.")
		return
	}

	startTime := time.Now().Unix()

	command := incRequest.ExecutionArgument
	if sensorDetails.ResponseActions == "controlled" {
		if !strings.HasPrefix(command, "script:") { 
			log.Printf("[WARNING] Invalid execution argument for controlled response action: %s. Must start with 'script:', which points to a valid cloud script.", command)
			return
		}
	}

	command = RCECleanup(command)

	var out string
	var err error
	if strings.HasPrefix(strings.ToLower(command), "script:") { 

		if strings.HasPrefix(command, "script:isolate") { 
			allowedIPs := []string{}

			// Nslookup the current backendUrl 
			if backendUrl != "" {
				parsedUrl, err := url.Parse(backendUrl)
				if err != nil {
					log.Printf("[ERROR] Failed to parse backend URL '%s': %s", backendUrl, err)
				} else {
					host := parsedUrl.Hostname()
					ips, err := net.LookupIP(host)
					if err != nil {
						log.Printf("[ERROR] Failed to lookup IP for host '%s': %s", host, err)
					} else {
						for _, ip := range ips {
							if ip.String() == "::1" || strings.HasPrefix(ip.String(), "127.0.0") {
								continue
							}

							allowedIPs = append(allowedIPs, ip.String())
						}
					}
				}
			}

			if len(allowedIPs) == 0 {
				out = "Failed to determine allowed IPs for isolation. Host isolation requires at least one allowed IP to be determined."
			} else {
				log.Printf("[WARNING] Isolating with URL %s. Allowed IPs: %#v", backendUrl, allowedIPs)

				err := isolateHost(allowedIPs) 
				if err != nil { 
					log.Printf("[ERROR] Failed to isolate host: %s", err)
					out = fmt.Sprintf("Failed to isolate host: %s", err.Error())
				} else {
					out = "Host isolated successfully"
					err = nil

					os.Setenv("HOST_ISOLATED", "true")
				}
			}
		} else if strings.HasPrefix(command, "script:unisolate") {
			err := unisolateHost()
			if err != nil {
				log.Printf("[ERROR] Failed to un-isolate host: %s", err)
			} else {
				out = "Host un-isolated successfully"
				os.Setenv("HOST_ISOLATED", "false")
			}

		} else if strings.HasPrefix(command, "script:remote_control") && sensorDetails.ResponseActions == "full" { 
			// Example Mouse Move: 
			// script:remote_control {"actions":[{"op":"mouse.move","params":{"x":600,"y":400}},{"op":"mouse.click","params":{"x":600,"y":400,"button":"left","delay_ms":100}}]}

			actualCommand := strings.TrimPrefix(command, "script:remote_control ")
			log.Printf("[WARNING] Executing remote control command: %s", actualCommand)

			parsedCommand := shuffle.RemoteControlActionBatch{}
			err := json.Unmarshal([]byte(actualCommand), &parsedCommand)
			if err != nil {
				out = fmt.Sprintf("Failed to parse remote control command JSON: %s", err.Error())
			} else {
				err = remoteControlBatch(parsedCommand)
				if err != nil { 
					out = fmt.Sprintf("Failed to execute remote control command: %s", err.Error())
				} else {
					out = fmt.Sprintf("Executed %d remote control commands", len(parsedCommand.Actions))
				}
			}

		} else if strings.HasPrefix(command, "script:screenshot") { 
			out = fmt.Sprintf("Screenshot capture of '%s' is not available yet", hostname)
			err = nil

			screenshotOutput, err := Screenshot()
			if err != nil { 
				log.Printf("[ERROR] Failed to capture screenshot: %s", err)
				out = fmt.Sprintf("Failed to capture screenshot: %s", err.Error())
			} else {
				// Upload it here to the files API if possible
				for scrIndex, screenshot := range screenshotOutput {
					base64Encoded := base64.StdEncoding.EncodeToString(screenshot.Image)
					screenshot.ImageBase64 = fmt.Sprintf("data:image/png;base64,%s", base64Encoded)
					screenshot.Image = []byte{}
					screenshotOutput[scrIndex] = screenshot
				}

				marshalledOutput, err := json.Marshal(screenshotOutput)
				if err != nil {
					log.Printf("[ERROR] Failed to marshal screenshot output: %s", err)
					out = fmt.Sprintf("Failed to marshal screenshot output: %s", err.Error())
				} else {
					out = string(marshalledOutput)
				}
			}

		} else if strings.HasPrefix(command, "script:cbom ") { 
			filepath := strings.TrimPrefix(command, "script:cbom ")
			out = fmt.Sprintf("CBOM scan of '%s' is not available yet", filepath)
			err = nil

			// For scanning a module at a specific path:
			//app.NewGenerator(moduleDir) - For scanning applications
			//bin.NewGenerator(binaryPath) - For scanning compiled binaries

			//generator, err := mod.NewGenerator(
			/*
			generator, err := app.NewGenerator(
				filepath,
			)
			if err != nil {
				log.Printf("[ERROR] Failed to create CBOM generator: %s", err)
				out = fmt.Sprintf("Failed to create CBOM gen: %s", err.Error())
			} else {
				bom, err := generator.Generate()
				if err != nil {
					log.Printf("[ERROR] Failed to generate CBOM: %s", err)
					out = fmt.Sprintf("Failed run cbom generate: %s", err.Error())
				} else {
					outBytes, err := json.Marshal(bom)
					if err != nil {
						log.Printf("[ERROR] Failed to marshal CBOM output: %s", err)
						out = fmt.Sprintf("Failed to marshal CBOM: %s", err.Error())
					} else {
						out = string(outBytes)
					}
				}
			}
			*/

		} else {
			log.Printf("[ERROR] Script-based response actions are not yet available. Cannot execute script: %s", command)

			out = "Command not available for this host"
			err = fmt.Errorf("the action is not recognized or you do not have permission to perform this action. Contact support@shuffler.io if this seems like a bug.")
		}
	} else { 
		if len(command) == 0 {
			return
		}

		if debug { 
			log.Printf("[DEBUG] RUNNING COMMAND '%s'", command)
		}

		out, err = RunCommandString(
			command,
			10*time.Second,
			func(line string) {
				if debug { 
					fmt.Println("DEBUG STREAM:", command, line)
				}
			},
		)
	}

	if debug && len(out) < 10000 { 
		log.Printf("[DEBUG] Command output: '%s'. Error: %s", out, err)
	}

	parsedResult := shuffle.RCEResult{
		Success: true,
		Hostname: hostname,
		Command: command,
		Output: out,
		Error: "",
	}

	if err != nil { 
		parsedResult.Success = false
		parsedResult.Error = err.Error()
	}

	marshalledResult, err := json.Marshal(parsedResult)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to marshal RCE result: %s", incRequest.ExecutionId, err)
		return
	}

	// From Orborus
	fullUrl := fmt.Sprintf("%s/api/v1/streams", backendUrl)
	topClient := shuffle.GetExternalClient(fullUrl)

	if debug { 
		log.Printf("[DEBUG] INCREQUEST: %#v", incRequest)
	}

	fullResult := shuffle.ActionResult{ 
		ExecutionId: incRequest.ExecutionId,
		Authorization: incRequest.Authorization,
		Action: shuffle.Action{
			AppName: "sensor",
			AppID: "sensor",
			ID: incRequest.Start,
		},
		StartedAt: startTime,
		CompletedAt: time.Now().Unix(),
		Result: string(marshalledResult),
	}

	fullResultData, err := json.Marshal(fullResult)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to marshal action result: %s", incRequest.ExecutionId, err)
		return 
	}

	req, err := http.NewRequest(
		"POST",
		fullUrl,
		bytes.NewBuffer([]byte(fullResultData)),
	)

	if err != nil { 
		log.Printf("[ERROR][%s] Failed to create HTTP request for response action result: %s", incRequest.ExecutionId, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := topClient.Do(req)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to send response action result: %s", incRequest.ExecutionId, err)
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR][%s] Failed to read response body after sending action result: %s", incRequest.ExecutionId, err)
		return
	}

	if resp.StatusCode != 200 {
		log.Printf("[ERROR][%s] Received non-200 response when sending action result to %s: %d. Body: %s", fullUrl, incRequest.ExecutionId, resp.StatusCode, string(respBody))
		return
	}

	log.Printf("[INFO][%s] Successfully sent command action result. Status: %d, Result: %s. Bytes sent: %d", incRequest.ExecutionId, resp.StatusCode, string(respBody), len(fullResultData))
}

// ListProcesses returns all running processes.
// On macOS this calls sysctl kern.proc under the hood.
// On Linux this reads /proc.
func ListProcesses() ([]shuffle.ProcessInfo, error) {
	switch runtime.GOOS {
	case "darwin":
		return listProcessesDarwin()
	case "linux":
		return listProcessesLinux()
	case "windows":
		return listProcessesWindows()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func listProcessesWindows() ([]shuffle.ProcessInfo, error) {
	return collect()
}

func listProcessesDarwin() ([]shuffle.ProcessInfo, error) {
	return collect()
}

func listProcessesLinux() ([]shuffle.ProcessInfo, error) {
	return collect()
}

// collect is identical on both platforms — gopsutil handles the syscall difference.
func collect() ([]shuffle.ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}

	out := make([]shuffle.ProcessInfo, 0, len(procs))
	for _, p := range procs {
		ppid, err := p.Ppid()
		if err != nil { 
			ppid = 0
		}

		tty, err  := p.Terminal() // "" if no controlling terminal
		if err != nil { 
			tty = ""
		}

		cmd, err  := p.Name()     // argv[0] basename
		if err != nil { 
			cmd = ""
		}

		user, err := p.Username()
		if err != nil { 
			user = ""
		}

		exePath, err := p.Exe()
		if err != nil {
			exePath = ""
		}

		// kernel threads and SIP-protected processes.
		args, err := p.CmdlineSlice()
		if err != nil {
			args = nil
		}
		args = scrubArgs(args)

		createdAt, err := p.CreateTime()
		if err != nil { 
			createdAt = 0
		}

		out = append(out, shuffle.ProcessInfo{
			PID:     p.Pid,
			PPID:    ppid,
			TTY:     tty,
			CommandLine: cmd,
			User: user,
			
			Args: args,
			CreationTime: createdAt,
			ExePath:  exePath,

			// Hash the binary on disk. Note: this is the file at rest, not the
			// in-memory image — a binary replaced after launch won't be caught here.
			SHA256:   cachedHashFile(exePath),
		})
	}

	if debug { 
		log.Printf("[INFO] Found %d processes", len(out))
	}

	return out, nil
}

func scrubArgs(args []string) []string {
	if len(args) == 0 {
		return args
	}

	out := make([]string, len(args))
	copy(out, args)

	for i, arg := range out {
		// Style 1: --flag=value or -f=value
		if eq := indexByte(arg, '='); eq >= 0 {
			key := arg[:eq]
			if isSecretKey(key) {
				out[i] = key + "=[REDACTED]"
			}
			continue
		}

		// Style 2/3: --flag value or -f value — redact the next element.
		if isSecretKey(arg) && i+1 < len(out) {
			out[i+1] = "[REDACTED]"
		}
	}

	return out
}

type cacheEntry struct {
	hash  string
	mtime time.Time
	size  int64
}

var (
	hashCache   = make(map[string]cacheEntry)
	hashCacheMu sync.Mutex
)

// cachedHashFile returns the SHA256 of the file at path.
// It only re-hashes if the file's mtime or size has changed since last call.
func cachedHashFile(path string) string {
	if path == "" {
		return ""
	}

	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	mtime := info.ModTime()
	size := info.Size()

	hashCacheMu.Lock()
	entry, ok := hashCache[path]
	hashCacheMu.Unlock()

	if ok && entry.mtime.Equal(mtime) && entry.size == size {
		return entry.hash
	}

	// Cache miss or file changed — hash it.
	hash := hashFile(path)
	if hash == "" {
		return ""
	}

	hashCacheMu.Lock()
	hashCache[path] = cacheEntry{hash: hash, mtime: mtime, size: size}
	hashCacheMu.Unlock()

	return hash
}

var secretKeywords = []string{
	"token",
	"secret",
	"password",
	"passwd",
	"apikey",
	"api_key",
	"api-key",
	"auth",
	"credential",
	"private_key",
	"private-key",
	"access_key",
	"access-key",
	"signing_key",
	"signing-key",
}

// isSecretKey returns true if the flag name contains a secret keyword.
func isSecretKey(flag string) bool {
	// Strip leading dashes so "--api-key" and "api-key" both match.
	lower := strings.ToLower(strings.TrimLeft(flag, "-"))
	for _, kw := range secretKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// hashFile computes the SHA256 of a file by streaming it —
// large binaries never fully land in memory.
func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}




// indexByte returns the index of the first occurrence of c in s, or -1.
// Using this instead of strings.IndexByte to avoid an extra import.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// NewScanner creates a new project scanner
func NewScanner() *Scanner {
	return &Scanner{
		results: make(chan shuffle.ProjectInfo),
		visited: make(map[string]bool),
	}
}

// extractGoPackages parses go.mod file and extracts packages with versions
func extractGoPackages(dir string) []shuffle.Software {
	goModPath := filepath.Join(dir, "go.mod")
	file, err := os.Open(goModPath)
	if err != nil {
		return []shuffle.Software{}
	}
	defer file.Close()

	var packages []shuffle.Software
	scanner := bufio.NewScanner(file)
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" && inRequire {
			inRequire = false
			continue
		}

		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			// Parse: package-name version
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				packages = append(packages, shuffle.Software{
					Name:    parts[0],
					Version: parts[1],
				})
			} else if len(parts) == 1 {
				packages = append(packages, shuffle.Software{
					Name:    parts[0],
					Version: "",
				})
			}
		}
	}

	return packages
}

// extractPythonPackages parses Python dependency files
func extractPythonPackages(dir string) []shuffle.Software {
	var packages []shuffle.Software

	// Try pyproject.toml first
	if data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml")); err == nil {
		packages = parsePyprojectToml(string(data))
		if len(packages) > 0 {
			return packages
		}
	}

	// Fall back to requirements.txt
	if data, err := os.ReadFile(filepath.Join(dir, "requirements.txt")); err == nil {
		packages = parseRequirementsTxt(string(data))
		if len(packages) > 0 {
			return packages
		}
	}

	// Try Pipfile
	if data, err := os.ReadFile(filepath.Join(dir, "Pipfile")); err == nil {
		packages = parsePipfile(string(data))
	}

	return packages
}

// parseRequirementsTxt extracts package names and versions from requirements.txt
func parseRequirementsTxt(content string) []shuffle.Software {
	var packages []shuffle.Software
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse: package>=1.0.0 or package==1.0.0, etc.
		var name, version string

		// Find first version specifier
		versionOps := []string{">=", "<=", "==", "~=", "!=", ">", "<", ";"}
		minIdx := len(line)
		for _, op := range versionOps {
			if idx := strings.Index(line, op); idx >= 0 && idx < minIdx {
				minIdx = idx
			}
		}

		if minIdx < len(line) {
			name = strings.TrimSpace(line[:minIdx])
			version = strings.TrimSpace(line[minIdx:])
		} else {
			name = line
			version = ""
		}

		if name != "" {
			packages = append(packages, shuffle.Software{
				Name:    name,
				Version: version,
			})
		}
	}

	return packages
}

// parsePyprojectToml extracts dependencies from pyproject.toml
func parsePyprojectToml(content string) []shuffle.Software {
	var packages []shuffle.Software
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "dependencies") || strings.Contains(line, "requires") {
			inDeps = true
			continue
		}

		if inDeps && strings.HasPrefix(line, "[") {
			inDeps = false
		}

		if inDeps && strings.HasPrefix(line, "\"") {
			// Extract package name from dependency string like: "django>=3.0,<4.0"
			pkg := strings.Trim(line, "\",")

			// Find first version specifier
			versionOps := []string{">=", "<=", "==", "~=", "!=", ">", "<", ";"}
			minIdx := len(pkg)
			for _, op := range versionOps {
				if idx := strings.Index(pkg, op); idx >= 0 && idx < minIdx {
					minIdx = idx
				}
			}

			var name, version string
			if minIdx < len(pkg) {
				name = strings.TrimSpace(pkg[:minIdx])
				version = strings.TrimSpace(pkg[minIdx:])
			} else {
				name = pkg
				version = ""
			}

			if name != "" {
				packages = append(packages, shuffle.Software{
					Name:    name,
					Version: version,
				})
			}
		}
	}

	return packages
}

// parsePipfile extracts dependencies from Pipfile
func parsePipfile(content string) []shuffle.Software {
	var packages []shuffle.Software
	inPackages := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "[packages]") {
			inPackages = true
			continue
		}

		if inPackages && strings.HasPrefix(line, "[") {
			inPackages = false
		}

		if inPackages && line != "" && !strings.HasPrefix(line, "[") {
			// Parse: package = "==1.0" or package = "*"
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.TrimSpace(strings.Join(parts[1:], "="))
				version = strings.Trim(version, "\"'")
				packages = append(packages, shuffle.Software{
					Name:    name,
					Version: version,
				})
			}
		}
	}

	return packages
}

// extractJavaScriptPackages parses package.json and extracts packages with versions
func extractJavaScriptPackages(dir string) []shuffle.Software {
	packageJsonPath := filepath.Join(dir, "package.json")
	data, err := os.ReadFile(packageJsonPath)
	if err != nil {
		return []shuffle.Software{}
	}

	var pkgData map[string]interface{}
	if err := json.Unmarshal(data, &pkgData); err != nil {
		return []shuffle.Software{}
	}

	var packages []shuffle.Software

	// Extract dependencies
	if deps, ok := pkgData["dependencies"].(map[string]interface{}); ok {
		for pkg, ver := range deps {
			version := ""
			if v, ok := ver.(string); ok {
				version = v
			}
			packages = append(packages, shuffle.Software{
				Name:    pkg,
				Version: version,
			})
		}
	}

	// Extract devDependencies
	if devDeps, ok := pkgData["devDependencies"].(map[string]interface{}); ok {
		for pkg, ver := range devDeps {
			version := ""
			if v, ok := ver.(string); ok {
				version = v
			}
			packages = append(packages, shuffle.Software{
				Name:    pkg,
				Version: version,
			})
		}
	}

	return packages
}

// extractJavaPackages parses Maven pom.xml or Gradle build files
func extractJavaPackages(dir string) []shuffle.Software {
	// Try Maven first
	pomPath := filepath.Join(dir, "pom.xml")
	if data, err := os.ReadFile(pomPath); err == nil {
		return parsePomXml(string(data))
	}

	// Try Gradle
	gradlePath := filepath.Join(dir, "build.gradle")
	if data, err := os.ReadFile(gradlePath); err == nil {
		return parseGradleBuild(string(data))
	}

	// Try Gradle Kotlin DSL
	gradleKtsPath := filepath.Join(dir, "build.gradle.kts")
	if data, err := os.ReadFile(gradleKtsPath); err == nil {
		return parseGradleBuild(string(data))
	}

	return []shuffle.Software{}
}

// parsePomXml extracts dependencies from Maven pom.xml
func parsePomXml(content string) []shuffle.Software {
	var packages []shuffle.Software
	inDeps := false
	var currentGroupId string

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "<dependencies>") {
			inDeps = true
			continue
		}
		if strings.Contains(line, "</dependencies>") {
			inDeps = false
			continue
		}

		if inDeps {
			if strings.Contains(line, "<groupId>") {
				currentGroupId = extractXmlValue(line, "groupId")
			}
			if strings.Contains(line, "<version>") && currentGroupId != "" {
				version := extractXmlValue(line, "version")
				packages = append(packages, shuffle.Software{
					Name:    currentGroupId,
					Version: version,
				})
				currentGroupId = ""
			}
		}
	}

	return packages
}

// parseGradleBuild extracts dependencies from Gradle build files
func parseGradleBuild(content string) []shuffle.Software {
	var packages []shuffle.Software
	inDeps := false

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "dependencies") || strings.Contains(line, "dependencies {") {
			inDeps = true
			continue
		}

		if inDeps && strings.HasPrefix(line, "}") {
			inDeps = false
			continue
		}

		if inDeps && (strings.HasPrefix(line, "implementation") ||
			strings.HasPrefix(line, "compile") ||
			strings.HasPrefix(line, "testImplementation")) {

			// Extract dependency string: implementation 'group:artifact:version'
			start := strings.Index(line, "'")
			end := strings.LastIndex(line, "'")
			if start >= 0 && end > start {
				dep := line[start+1 : end]
				parts := strings.Split(dep, ":")
				if len(parts) >= 3 {
					packages = append(packages, shuffle.Software{
						Name:    parts[0] + ":" + parts[1],
						Version: parts[2],
					})
				} else if len(parts) >= 2 {
					packages = append(packages, shuffle.Software{
						Name:    parts[0],
						Version: parts[1],
					})
				}
			}
		}
	}

	return packages
}

// extractRubyPackages parses Gemfile for Ruby dependencies
func extractRubyPackages(dir string) []shuffle.Software {
	gemfilePath := filepath.Join(dir, "Gemfile")
	data, err := os.ReadFile(gemfilePath)
	if err != nil {
		return []shuffle.Software{}
	}

	return parseGemfile(string(data))
}

// parseGemfile extracts gem names and versions from Gemfile
func parseGemfile(content string) []shuffle.Software {
	var packages []shuffle.Software

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and blank lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Match: gem 'gem-name' or gem "gem-name" or gem 'gem-name', '~> 1.0'
		if strings.HasPrefix(line, "gem") {
			// Extract gem name and version
			var name, version string

			if strings.Contains(line, "'") {
				start := strings.Index(line, "'") + 1
				end := strings.Index(line[start:], "'")
				if end > 0 {
					name = line[start : start+end]
					// Look for version specification after the name
					rest := line[start+end+1:]
					if strings.Contains(rest, "'") || strings.Contains(rest, "\"") {
						// Extract version from second quoted string
						var versionStart, versionEnd int
						if strings.Contains(rest, "'") {
							versionStart = strings.Index(rest, "'") + 1
							versionEnd = strings.Index(rest[versionStart:], "'")
						} else if strings.Contains(rest, "\"") {
							versionStart = strings.Index(rest, "\"") + 1
							versionEnd = strings.Index(rest[versionStart:], "\"")
						}
						if versionEnd > 0 {
							version = rest[versionStart : versionStart+versionEnd]
						}
					}
				}
			} else if strings.Contains(line, "\"") {
				start := strings.Index(line, "\"") + 1
				end := strings.Index(line[start:], "\"")
				if end > 0 {
					name = line[start : start+end]
					// Look for version specification after the name
					rest := line[start+end+1:]
					if strings.Contains(rest, "'") || strings.Contains(rest, "\"") {
						var versionStart, versionEnd int
						if strings.Contains(rest, "'") {
							versionStart = strings.Index(rest, "'") + 1
							versionEnd = strings.Index(rest[versionStart:], "'")
						} else if strings.Contains(rest, "\"") {
							versionStart = strings.Index(rest, "\"") + 1
							versionEnd = strings.Index(rest[versionStart:], "\"")
						}
						if versionEnd > 0 {
							version = rest[versionStart : versionStart+versionEnd]
						}
					}
				}
			}

			if name != "" {
				packages = append(packages, shuffle.Software{
					Name:    name,
					Version: version,
				})
			}
		}
	}

	return packages
}

// extractDotnetPackages parses .NET project files for dependencies
func extractDotnetPackages(dir string) []shuffle.Software {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []shuffle.Software{}
	}

	// Find the first .csproj, .vbproj, or .fsproj file
	var projFile string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".csproj") ||
			strings.HasSuffix(name, ".vbproj") ||
			strings.HasSuffix(name, ".fsproj") {
			projFile = filepath.Join(dir, name)
			break
		}
	}

	if projFile == "" {
		return []shuffle.Software{}
	}

	data, err := os.ReadFile(projFile)
	if err != nil {
		return []shuffle.Software{}
	}

	return parseDotnetProjectFile(string(data))
}

// parseDotnetProjectFile extracts NuGet package references from .csproj/.vbproj/.fsproj
func parseDotnetProjectFile(content string) []shuffle.Software {
	var packages []shuffle.Software

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Look for <PackageReference Include="PackageName" Version="..." />
		if strings.Contains(line, "PackageReference") && strings.Contains(line, "Include") {
			// Extract Include attribute value (package name)
			var pkgName string
			start := strings.Index(line, "Include=\"") + len("Include=\"")
			end := strings.Index(line[start:], "\"")
			if end > 0 {
				pkgName = line[start : start+end]
			}

			// Extract Version attribute value
			var version string
			if versionIdx := strings.Index(line, "Version=\""); versionIdx >= 0 {
				start := versionIdx + len("Version=\"")
				end := strings.Index(line[start:], "\"")
				if end > 0 {
					version = line[start : start+end]
				}
			}

			if pkgName != "" {
				packages = append(packages, shuffle.Software{
					Name:    pkgName,
					Version: version,
				})
			}
		}
	}

	return packages
}

// extractXmlValue is a helper to extract simple XML tag values
func extractXmlValue(line string, tag string) string {
	openTag := "<" + tag + ">"
	closeTag := "</" + tag + ">"

	start := strings.Index(line, openTag)
	end := strings.Index(line, closeTag)

	if start >= 0 && end > start {
		return line[start+len(openTag) : end]
	}

	return ""
}
