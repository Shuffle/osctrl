//go:build !windows 

package osctrl 

import ( 
	"time"
	"log"
	"context"
	"os/exec"
	"bytes"
	"io"
	"syscall"
	"fmt"
	"os"
	"errors"
	"path/filepath"
	"strings"
	"runtime"
	"bufio"
	"encoding/json"
	"strconv"

	"github.com/shuffle/shuffle-shared"
)

func RunCommandString(command string, timeout time.Duration, onStream StreamFn) (string, error) {
	if debug { 
		log.Printf("[DEBUG] Running command (timeout: %#v): '%s'", timeout, command)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return "", err
	}

	var out bytes.Buffer

	stream := func(r io.ReadCloser) {
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				out.Write(buf[:n])
				if onStream != nil {
					onStream(string(buf[:n]))
				}
			}
			if err != nil {
				return
			}
		}
	}

	go stream(stdout)
	go stream(stderr)

	// IMPORTANT: wait in separate goroutine
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return out.String(), err

	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return out.String(), errors.New(fmt.Sprintf("process timeout after %s", timeout))
	}	
}


// captureDisplay captures a single display by 1-based index.
func captureDisplay(display int) ([]byte, error) {
	path := filepath.Join(
		os.TempDir(),
		fmt.Sprintf("edr-%d-d%d.png", time.Now().UnixNano(), display),
	)
	defer os.Remove(path)

	// Flags:
	//   -x      silent (no shutter sound)
	//   -t png  output format
	//   -D n    display index (1 = primary)
	cmd := exec.Command("screencapture", "-x", "-t", "png", "-D", fmt.Sprintf("%d", display), path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, errors.New(fmt.Sprintf("screencapture display %d: %w — %s", display, err, out))
	}

	// An out-of-range display index causes screencapture to exit 0 but write
	// nothing. Treat a missing output file as end-of-displays.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("display %d produced no output", display))
	}
	return data, nil
}

func IsElevated() bool {
	return os.Geteuid() == 0
}

func ListCodeScannerProjects() []shuffle.ProjectInfo {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Printf("[ERROR] Problem in codescanner (1): %v\n", err)
	}

	scanner := NewScanner()
	projects, err := scanner.Scan(homeDir)
	if err != nil {
		log.Printf("[ERROR] Problem in codescanner (2): %v\n", err)
	} 

	parsedProjects := []shuffle.ProjectInfo{}
	for _, project := range projects { 
		if len(project.Path) == 0 {
			continue
		}

		if project.Packages == nil || len(project.Packages) == 0 {
			continue
		}

		if strings.Contains(project.Path, "/go/pkg/mod") {
			continue
		}

		parsedProjects = append(parsedProjects, project)
	}

	return parsedProjects 
}

// Scan starts scanning from the given root directory
func (s *Scanner) Scan(rootDir string) ([]shuffle.ProjectInfo, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("invalid root directory: %w", err))
	}

	// Start the scanner goroutine
	s.wg.Add(1)
	go s.scanDir(absRoot)

	// Collect results in a separate goroutine
	results := make([]shuffle.ProjectInfo, 0)
	done := make(chan bool)

	go func() {
		for project := range s.results {
			results = append(results, project)
		}
		done <- true
	}()

	// Wait for all scanning to complete
	s.wg.Wait()
	close(s.results)
	<-done

	return results, nil
}

// scanDir recursively scans a directory for projects (runs in goroutine)
func (s *Scanner) scanDir(dir string) {
	defer s.wg.Done()

	// Prevent infinite loops from symlinks
	s.mu.Lock()
	if s.visited[dir] {
		s.mu.Unlock()
		return
	}
	s.visited[dir] = true
	s.mu.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return // Skip unreadable directories
	}

	for _, entry := range entries {
		// Skip hidden files and common non-project directories
		if shouldSkip(entry.Name()) {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())

		if entry.IsDir() {
			// Check if this directory is a project
			if projectType := detectProjectType(fullPath); projectType != "" {
				packages := extractPackages(fullPath, projectType)
				s.results <- shuffle.ProjectInfo{
					Path:     fullPath,
					Type:     projectType,
					Packages: packages,
				}
				// Don't recurse into found projects (to avoid duplicates)
				continue
			}

			// Recurse into subdirectory in a new goroutine
			s.wg.Add(1)
			go s.scanDir(fullPath)
		}
	}
}


// shouldSkip returns true if a directory should be skipped
func shouldSkip(name string) bool {
	skipDirs := map[string]bool{
		".git":        true,
		".hg":         true,
		"node_modules": true,
		"vendor":      true,
		".venv":       true,
		"venv":        true,
		".env":        true,
		".vscode":     true,
		".idea":       true,
		"dist":        true,
		"build":       true,
		"target":      true,
		".cache":      true,
	}

	if strings.HasPrefix(name, ".") && name != "." {
		return true // Skip hidden dirs in general
	}

	return skipDirs[name]
}

// detectProjectType checks if a directory is a project and returns its type
func detectProjectType(dir string) string {
	// Check for Go project
	if shuffle.FileExists(filepath.Join(dir, "go.mod")) {
		return "golang"
	}

	// Check for Python project
	if shuffle.FileExists(filepath.Join(dir, "pyproject.toml")) ||
		shuffle.FileExists(filepath.Join(dir, "requirements.txt")) ||
		shuffle.FileExists(filepath.Join(dir, "Pipfile")) {
		return "python"
	}

	// Check for JavaScript/TypeScript project
	if shuffle.FileExists(filepath.Join(dir, "package.json")) {
		return "javascript"
	}

	// Check for Java project
	if shuffle.FileExists(filepath.Join(dir, "pom.xml")) ||
		shuffle.FileExists(filepath.Join(dir, "build.gradle")) ||
		shuffle.FileExists(filepath.Join(dir, "build.gradle.kts")) {
		return "java"
	}

	// Check for Ruby project
	if shuffle.FileExists(filepath.Join(dir, "Gemfile")) ||
		shuffle.FileExists(filepath.Join(dir, "Rakefile")) {
		return "ruby"
	}

	// Check for .NET project
	if shuffle.FileExists(filepath.Join(dir, "*.csproj")) ||
		shuffle.FileExists(filepath.Join(dir, "*.vbproj")) ||
		shuffle.FileExists(filepath.Join(dir, "*.fsproj")) ||
		shuffle.FileExists(filepath.Join(dir, ".csproj")) ||
		shuffle.FileExists(filepath.Join(dir, ".vbproj")) ||
		shuffle.FileExists(filepath.Join(dir, ".fsproj")) {
		return "dotnet"
	}
	// Also check for .NET by looking for project files with glob
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasSuffix(name, ".csproj") ||
				strings.HasSuffix(name, ".vbproj") ||
				strings.HasSuffix(name, ".fsproj") {
				return "dotnet"
			}
		}
	}

	return ""
}

// extractPackages reads the appropriate dependency file and extracts package names with versions
func extractPackages(dir string, projectType string) []shuffle.Software {
	switch projectType {
	case "golang":
		return extractGoPackages(dir)
	case "python":
		return extractPythonPackages(dir)
	case "javascript":
		return extractJavaScriptPackages(dir)
	case "java":
		return extractJavaPackages(dir)
	case "ruby":
		return extractRubyPackages(dir)
	case "dotnet":
		return extractDotnetPackages(dir)
	}
	return []shuffle.Software{}
}

// EDR and Telemetry Functions
// NewAuditLogCollector creates a new audit log collector for the current platform
func NewAuditLogCollector(config shuffle.TelemetryConfig) (*AuditLogCollector, error) {
	platform := runtime.GOOS

	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}

	if config.FlushInterval == 0 {
		config.FlushInterval = 10 * time.Second
	}

	collector := &AuditLogCollector{
		Config:     config,
		Platform:   platform,
		LogChannel: make(chan shuffle.AuditLogEntry, config.BufferSize),
		StopChan:   make(chan bool),
	}

	return collector, nil
}

func (c *AuditLogCollector) LogCollectorStart(ctx context.Context) error {
	if !c.Config.Enabled {
		return nil
	}

	auditLogEnabled := false
	for _, mode := range c.Config.Modes {
		if mode == "audit_log" {
			auditLogEnabled = true
			break
		}
	}

	if !auditLogEnabled {
		return nil
	}

	log.Printf("[INFO] Starting audit log collector for platform: %s", c.Platform)

	switch c.Platform {
	case "linux":
		go c.collectLinuxAuditLogs(ctx)
	case "darwin":
		go c.collectMacOSAuditLogs(ctx)
	default:
		return errors.New(fmt.Sprintf("unsupported platform: %s", c.Platform))
	}

	go c.processTelemetryLogs(ctx)

	return nil
}

// Stop stops the audit log collection
func (c *AuditLogCollector) Stop() {
	log.Printf("[INFO] Stopping audit log collector")
	close(c.StopChan)
}

// collectLinuxAuditLogs collects audit logs on Linux systems
func (c *AuditLogCollector) collectLinuxAuditLogs(ctx context.Context) {
	// Check for auditd logs
	auditLogPath := "/var/log/audit/audit.log"
	syslogPath := "/var/log/syslog"
	journalAvailable := c.IsJournalAvailable()

	// Use journalctl if available
	if journalAvailable {
		go c.collectJournalLogs(ctx)
	}

	// Monitor audit.log if it exists
	if _, err := os.Stat(auditLogPath); err == nil {
		go c.tailLogFile(ctx, auditLogPath, "auditd")
	}

	// Monitor syslog
	if _, err := os.Stat(syslogPath); err == nil {
		go c.tailLogFile(ctx, syslogPath, "syslog")
	}
}

func (c *AuditLogCollector) collectMacOSAuditLogs(ctx context.Context) {
	go c.collectMacOSSecurityLogs(ctx)
}

// collectMacOSSecurityLogs collects all security-relevant logs with one predicate
func (c *AuditLogCollector) collectMacOSSecurityLogs(ctx context.Context) {
	log.Printf("[INFO] Starting macOS security log collection")

	predicate := `(subsystem == "com.apple.opendirectoryd" && category == "auth") ||
		process == "login" ||
		process == "sshd" ||
		process == "sudo" ||
		process == "su"`

	cmd := exec.Command("log", "stream",
		"--predicate", predicate,
		"--info", "--debug",
		"--style", "json")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[ERROR] Failed to create stdout pipe for security log stream: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[ERROR] Failed to start security log stream: %v", err)
		return
	}

	log.Printf("[INFO] Successfully started security log stream")

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return
		case <-c.StopChan:
			cmd.Process.Kill()
			return
		default:
			line := scanner.Text()
			if line != "" {
				c.parseMacOSLogEntry(line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] Error reading security log stream: %v", err)
	}
}

func (c *AuditLogCollector) parseMacOSLogEntry(line string) {
	// First, let's see what we're actually getting
	log.Printf("[DEBUG] Raw log line: %s", line)

	var logData map[string]interface{}
	if err := json.Unmarshal([]byte(line), &logData); err != nil {
		log.Printf("[ERROR] Failed to parse JSON: %v", err)
		// If JSON parsing fails, treat it as plain text
		c.parseSimpleMacOSLogEntry(line)
		return
	}

	log.Printf("[DEBUG] Parsed JSON log entry: %v", logData)

	entry := shuffle.AuditLogEntry{
		Timestamp: time.Now(),
		Platform:  "darwin",
		RawData:   line,
		Metadata:  logData,
	}

	if eventType, ok := logData["eventType"].(string); ok {
		entry.EventType = eventType
	}

	if eventMessage, ok := logData["eventMessage"].(string); ok {
		entry.Message = eventMessage
	}

	if processID, ok := logData["processID"].(float64); ok {
		entry.ProcessInfo = &shuffle.ProcessInfo{
			PID: int32(processID),
		}

		if processImagePath, ok := logData["processImagePath"].(string); ok {
			entry.ProcessInfo.ProcessName = filepath.Base(processImagePath)
		}
	}

	if c.shouldFilterLog(&entry) {
		return
	}

	select {
	case c.LogChannel <- entry:
	default:
		// log.Printf("[WARNING] Log channel full, dropping log entry")
	}
}

func (c *AuditLogCollector) parseSimpleMacOSLogEntry(line string) {
	// this just looks for keywords in the log line
	// not sure how reliable this is, but it's a start lol
	lowerLine := strings.ToLower(line)
	isSecurityRelevant := strings.Contains(lowerLine, "login") ||
		strings.Contains(lowerLine, "auth") ||
		strings.Contains(lowerLine, "sudo") ||
		strings.Contains(lowerLine, "password") ||
		strings.Contains(lowerLine, "session") ||
		strings.Contains(lowerLine, "security") ||
		strings.Contains(lowerLine, "loginwindow") ||
		strings.Contains(lowerLine, "securityd")

	if !isSecurityRelevant {
		return
	}

	entry := shuffle.AuditLogEntry{
		Timestamp: time.Now(),
		Platform:  "darwin",
		Source:    "unified_log",
		Message:   line,
		RawData:   line,
		EventType: "security",
	}

	// Basic process extraction from log format
	if strings.Contains(line, ": ") {
		parts := strings.Split(line, ": ")
		if len(parts) > 1 {
			processField := parts[0]
			if strings.Contains(processField, "[") {
				procParts := strings.Split(processField, "[")
				if len(procParts) > 0 {
					entry.ProcessInfo = &shuffle.ProcessInfo{
						ProcessName: strings.TrimSpace(procParts[0]),
					}
				}
			}
		}
	}

	if c.shouldFilterLog(&entry) {
		return
	}

	select {
	case c.LogChannel <- entry:
	default:
		// Channel full, drop the log
	}
}

// collectMacOSAuthLogs monitors auth.log and system authentication events
func (c *AuditLogCollector) collectMacOSAuthLogs(ctx context.Context) {
	log.Printf("[INFO] Starting macOS auth log collection")

	// Just monitor some basic log files that might exist
	logPaths := []string{
		"/var/log/auth.log",
		"/var/log/system.log",
		"/var/log/secure.log",
	}

	for _, logPath := range logPaths {
		if _, err := os.Stat(logPath); err == nil {
			log.Printf("[INFO] Monitoring log file: %s", logPath)
			go c.tailLogFile(ctx, logPath, filepath.Base(logPath))
		}
	}
}

// collectMacOSBSMaudit collects from macOS BSM audit system
func (c *AuditLogCollector) collectMacOSBSMaudit(ctx context.Context) {
	// Check if audit is enabled
	cmd := exec.Command("sudo", "audit", "-s")
	if err := cmd.Run(); err != nil {
		log.Printf("[WARNING] BSM audit not available or not enabled: %v", err)
		return
	}

	// Monitor current audit trail
	auditDir := "/var/audit"
	if _, err := os.Stat(auditDir); err != nil {
		log.Printf("[WARNING] Audit directory not accessible: %v", err)
		return
	}

	// Use praudit to read audit records in real-time
	cmd = exec.Command("sudo", "praudit", "-l")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[ERROR] Failed to create stdout pipe for praudit: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[ERROR] Failed to start praudit: %v", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return
		case <-c.StopChan:
			cmd.Process.Kill()
			return
		default:
			line := scanner.Text()
			c.parseBSMAuditEntry(line)
		}
	}
}

// parseBSMAuditEntry parses BSM audit entries
func (c *AuditLogCollector) parseBSMAuditEntry(line string) {
	entry := shuffle.AuditLogEntry{
		Timestamp: time.Now(),
		Platform:  "darwin",
		Source:    "bsm_audit",
		Message:   line,
		RawData:   line,
		EventType: "audit",
	}

	// Extract process info if available (basic parsing)
	if strings.Contains(line, "process") {
		// This is a simplified parser - BSM audit format is complex
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "process" && i+1 < len(fields) {
				entry.ProcessInfo = &shuffle.ProcessInfo{
					ProcessName: fields[i+1],
				}
				break
			}
		}
	}

	if c.shouldFilterLog(&entry) {
		return
	}

	select {
	case c.LogChannel <- entry:
	default:
		// Channel full, drop the log
	}
}

func (c *AuditLogCollector) collectJournalLogs(ctx context.Context) {
	cmd := exec.Command("journalctl", "-f", "-o", "json", "--since", "now")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[ERROR] Failed to create stdout pipe for journalctl: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[ERROR] Failed to start journalctl: %v", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			return
		case <-c.StopChan:
			cmd.Process.Kill()
			return
		default:
			line := scanner.Text()
			c.parseJournalEntry(line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[ERROR] Error reading journalctl: %v", err)
	}
}

// parseJournalEntry parses a systemd journal entry
func (c *AuditLogCollector) parseJournalEntry(line string) {
	var journalData map[string]interface{}
	if err := json.Unmarshal([]byte(line), &journalData); err != nil {
		return
	}

	entry := shuffle.AuditLogEntry{
		Timestamp: time.Now(),
		Platform:  "linux",
		Source:    "journal",
		RawData:   line,
		Metadata:  journalData,
	}

	// Extract standard journal fields
	if priority, ok := journalData["PRIORITY"].(string); ok {
		entry.Level = c.priorityToLevel(priority)
	}

	if message, ok := journalData["MESSAGE"].(string); ok {
		entry.Message = message
	}

	if syslogID, ok := journalData["SYSLOG_IDENTIFIER"].(string); ok {
		entry.EventType = syslogID
	}

	// Process information
	if pid, ok := journalData["_PID"].(string); ok {
		pidInt, _ := strconv.Atoi(pid)
		entry.ProcessInfo = &shuffle.ProcessInfo{
			PID: int32(pidInt),
		}

		if comm, ok := journalData["_COMM"].(string); ok {
			entry.ProcessInfo.ProcessName = comm
		}

		if cmdline, ok := journalData["_CMDLINE"].(string); ok {
			entry.ProcessInfo.CommandLine = cmdline
		}
	}

	// User information
	if uid, ok := journalData["_UID"].(string); ok {
		entry.UserInfo = &shuffle.UserInfo{
			UserID: uid,
		}
	}

	// Apply filters
	if c.shouldFilterLog(&entry) {
		return
	}

	select {
	case c.LogChannel <- entry:
	default:
		// Channel full, drop the log
	}
}

// tailLogFile monitors a log file for new entries
func (c *AuditLogCollector) tailLogFile(ctx context.Context, filepath string, source string) {
	file, err := os.Open(filepath)
	if err != nil {
		log.Printf("[ERROR] Failed to open log file %s: %v", filepath, err)
		return
	}
	defer file.Close()

	// Seek to end of file
	file.Seek(0, 2)

	scanner := bufio.NewScanner(file)
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.StopChan:
			return
		default:
			if scanner.Scan() {
				line := scanner.Text()
				entry := shuffle.AuditLogEntry{
					Timestamp: time.Now(),
					Platform:  c.Platform,
					Source:    source,
					Message:   line,
					RawData:   line,
				}

				// Apply filters
				if c.shouldFilterLog(&entry) {
					continue
				}

				select {
				case c.LogChannel <- entry:
				default:
					// Channel full, drop the log
				}
			} else {
				// No new data, sleep briefly
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func (c *AuditLogCollector) processTelemetryLogs(ctx context.Context) {
	buffer := make([]shuffle.AuditLogEntry, 0, c.Config.BufferSize)
	ticker := time.NewTicker(c.Config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.flushLogs(buffer)
			return
		case <-c.StopChan:
			c.flushLogs(buffer)
			return
		case entry := <-c.LogChannel:
			buffer = append(buffer, entry)
			if len(buffer) >= c.Config.BufferSize {
				c.flushLogs(buffer)
				buffer = buffer[:0]
			}
		case <-ticker.C:
			if len(buffer) > 0 {
				c.flushLogs(buffer)
				buffer = buffer[:0]
			}
		}
	}
}

// flushLogs outputs collected logs (for now just printing)
func (c *AuditLogCollector) flushLogs(logs []shuffle.AuditLogEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, log := range logs {
		// For now, just print the logs
		fmt.Printf("[AUDIT] %s | %s | %s | %s\n",
			log.Timestamp.Format(time.RFC3339),
			log.Platform,
			log.EventType,
			log.Message)
	}
}

func (c *AuditLogCollector) shouldFilterLog(entry *shuffle.AuditLogEntry) bool {
	for _, filter := range c.Config.Filters {
		switch filter.Type {
		case "event_type":
			if len(filter.Include) > 0 {
				included := false
				for _, inc := range filter.Include {
					if strings.Contains(entry.EventType, inc) {
						included = true
						break
					}
				}
				if !included {
					return true
				}
			}

			for _, exc := range filter.Exclude {
				if strings.Contains(entry.EventType, exc) {
					return true
				}
			}
		case "message":
			if len(filter.Include) > 0 {
				included := false
				for _, inc := range filter.Include {
					if strings.Contains(entry.Message, inc) {
						included = true
						break
					}
				}
				if !included {
					return true
				}
			}

			for _, exc := range filter.Exclude {
				if strings.Contains(entry.Message, exc) {
					return true
				}
			}
		}
	}

	return false
}

// isJournalAvailable checks if systemd journal is available
func (c *AuditLogCollector) IsJournalAvailable() bool {
	cmd := exec.Command("which", "journalctl")
	err := cmd.Run()
	return err == nil
}

// priorityToLevel converts systemd priority to log level
func (c *AuditLogCollector) priorityToLevel(priority string) string {
	switch priority {
	case "0", "1", "2", "3":
		return "ERROR"
	case "4":
		return "WARNING"
	case "5", "6":
		return "INFO"
	case "7":
		return "DEBUG"
	default:
		return "INFO"
	}
}
