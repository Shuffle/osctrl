//go:build windows

package osctrl 

import (
	"strings"
	"encoding/json"
	"log"
	"os"
	"bytes"
	"time"
	"context"
	"io"
	"errors"
	"fmt"
	"path/filepath"
	"io/fs"

	"unsafe" // for pointer control. Not ideal, but ok
	"syscall"
	"os/exec"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"github.com/shuffle/shuffle-shared"
)

func scanRegistryUninstall() []shuffle.Software {
	roots := []struct {
		key  registry.Key
		path string
		flag uint32
		source string
	}{
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_64KEY, "registry-lm-64"},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, registry.WOW64_32KEY, "registry-lm-32"},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`, 0, "registry-cu"},
	}

	var out []shuffle.Software

	for _, r := range roots {
		k, err := registry.OpenKey(r.key, r.path, registry.READ|r.flag)
		if err != nil {
			continue
		}
		defer k.Close()

		names, _ := k.ReadSubKeyNames(-1)

		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.READ|r.flag)
			if err != nil {
				continue
			}

			name, _, _ := sk.GetStringValue("DisplayName")
			version, _, _ := sk.GetStringValue("DisplayVersion")
			path, _, _ := sk.GetStringValue("InstallLocation")

			sk.Close()

			if name == "" {
				continue
			}

			out = append(out, shuffle.Software{
				Name:    name,
				Version: version,
				Path:    path,
				Source:  r.source,
			})
		}
	}

	return out
}

// Infrastructure package prefixes to drop.
// These are runtime components, not user-installed apps.
var appxSkipPrefixes = []string{
    "Microsoft.NET.",
    "Microsoft.VCLibs.",
    "Microsoft.VCRedist.",
    "Microsoft.UI.",
    "Microsoft.Windows.",
    "Microsoft.Xbox",
    "Microsoft.Advertising.",
    "Microsoft.Services.",
    "Windows.",
    "MicrosoftCorporationII.",
}

func scanAppx() []shuffle.Software {
    cmd := `Get-AppxPackage | Select Name, Version | ConvertTo-Json -Compress`
    out, err := exec.Command("powershell", "-NoProfile", "-Command", cmd).Output()
    if err != nil || len(out) == 0 {
        return nil
    }

    type pkg struct {
        Name    string
        Version string
    }

    // ConvertTo-Json emits a bare object (not array) when there's exactly
    // one result. Try array first, fall back to single object.
    var packages []pkg
    if err := json.Unmarshal(out, &packages); err != nil {
        var single pkg
        if err2 := json.Unmarshal(out, &single); err2 != nil {
            return nil
        }
        packages = []pkg{single}
    }

    var res []shuffle.Software
    for _, p := range packages {
        if isInfraAppx(p.Name) {
            continue
        }
        res = append(res, shuffle.Software{
            Name:    p.Name,
            Version: p.Version,
            Source:  "appx",
        })
    }
    return res
}

func isInfraAppx(name string) bool {
    for _, prefix := range appxSkipPrefixes {
        if strings.HasPrefix(name, prefix) {
            return true
        }
    }
    return false
}

var roots = []string{
	`C:\Program Files`,
	`C:\Program Files (x86)`,
}

func scanProgramFiles() []shuffle.Software {
	var out []shuffle.Software

	for _, root := range roots {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			// limit depth (cheap heuristic)
			if strings.Count(path, string(os.PathSeparator)) > 4 {
				return filepath.SkipDir
			}

			if d.IsDir() {
				return nil
			}

			if !strings.HasSuffix(strings.ToLower(d.Name()), ".exe") {
				return nil
			}

			name, version := getFileVersion(path)
			if name == "" {
				return nil
			}

			out = append(out, shuffle.Software{
				Name:    name,
				Version: version,
				Path:    path,
				Source:  "filesystem",
			})

			return nil
		})
	}

	return out
}

var (
    modVersion             = windows.NewLazySystemDLL("version.dll")
    procGetFileVersionInfo = modVersion.NewProc("GetFileVersionInfoW")
    procGetFileVersionSize = modVersion.NewProc("GetFileVersionInfoSizeW")
    procVerQueryValue      = modVersion.NewProc("VerQueryValueW")
)

func getFileVersion(path string) (name, version string) {
    pathPtr, err := windows.UTF16PtrFromString(path)
    if err != nil {
        return "", ""
    }

    // First call: get required buffer size
    size, _, _ := procGetFileVersionSize.Call(
        uintptr(unsafe.Pointer(pathPtr)),
        0,
    )
    if size == 0 {
        return "", ""
    }

    buf := make([]byte, size)

    // Second call: fill the buffer
    ret, _, _ := procGetFileVersionInfo.Call(
        uintptr(unsafe.Pointer(pathPtr)),
        0,
        size,
        uintptr(unsafe.Pointer(&buf[0])),
    )
    if ret == 0 {
        return "", ""
    }

    // Query the translation table to find the right language/codepage pair
    type langCodepage struct{ lang, codepage uint16 }
    var translations *langCodepage
    var transLen uint32

    ret, _, _ = procVerQueryValue.Call(
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(`\VarFileInfo\Translation`))),
        uintptr(unsafe.Pointer(&translations)),
        uintptr(unsafe.Pointer(&transLen)),
    )
    if ret == 0 || transLen == 0 {
        return "", ""
    }

    // Use the first available translation
    lang := fmt.Sprintf(`\StringFileInfo\%04x%04x\`, translations.lang, translations.codepage)

    name = queryStringValue(buf, lang+"ProductName")
    version = queryStringValue(buf, lang+"ProductVersion")
    return name, version
}

func queryStringValue(buf []byte, key string) string {
    keyPtr, err := windows.UTF16PtrFromString(key)
    if err != nil {
        return ""
    }
    var valPtr uintptr
    var valLen uint32
    ret, _, _ := procVerQueryValue.Call(
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(unsafe.Pointer(keyPtr)),
        uintptr(unsafe.Pointer(&valPtr)),
        uintptr(unsafe.Pointer(&valLen)),
    )
    if ret == 0 || valLen == 0 {
        return ""
    }
    // valPtr points into buf, valLen is in characters (UTF-16)
    utf16Slice := unsafe.Slice((*uint16)(unsafe.Pointer(valPtr)), valLen)
    return windows.UTF16ToString(utf16Slice)
}


func scanWinget() []shuffle.Software {
    out, err := exec.Command(
        "winget", "list",
        "--disable-interactivity",
        "--accept-source-agreements",
    ).Output()
    if err != nil || len(out) == 0 {
        return nil
    }

    lines := strings.Split(string(out), "\n")

    // Find the header line — it contains "Name" and "Id"
    headerIdx := -1
    for i, l := range lines {
        if strings.Contains(l, "Name") && strings.Contains(l, "Id") {
            headerIdx = i
            break
        }
    }
    if headerIdx < 0 || headerIdx+2 >= len(lines) {
        return nil
    }

    header := lines[headerIdx]

    // Column start positions by header label
    nameCol    := strings.Index(header, "Name")
    idCol      := strings.Index(header, "Id")
    versionCol := strings.Index(header, "Version")
    sourceCol  := strings.Index(header, "Source")  // may be -1

    if nameCol < 0 || idCol < 0 || versionCol < 0 {
        return nil
    }

    // Skip header + separator line (headerIdx+1 is "----")
    var res []shuffle.Software
    for _, line := range lines[headerIdx+2:] {
        // Trim Windows line endings; skip short/empty lines
        line = strings.TrimRight(line, "\r")
        if len(line) < versionCol+1 {
            continue
        }

        name    := columnSlice(line, nameCol, idCol)
        version := columnSlice(line, versionCol, sourceCol)

        if name == "" {
            continue
        }
        res = append(res, shuffle.Software{
            Name:    name,
            Version: version,
            Source:  "winget",
        })
    }
    return res
}

// columnSlice extracts text between start and end column positions,
// trimming whitespace. If end is -1 (column not present), reads to EOL.
func columnSlice(line string, start, end int) string {
    if start >= len(line) {
        return ""
    }
    if end < 0 || end >= len(line) {
        return strings.TrimSpace(line[start:])
    }
    return strings.TrimSpace(line[start:end])
}

func dedupe(in []shuffle.Software) []shuffle.Software {
	seen := map[string]bool{}
	var out []shuffle.Software

	for _, s := range in {
		key := strings.ToLower(s.Name + "|" + s.Version)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}

	return out
}

func ListInstalledSoftware() []shuffle.Software {
	var all []shuffle.Software

	all = append(all, scanRegistryUninstall()...)
	all = append(all, scanAppx()...)
	all = append(all, scanProgramFiles()...)
	all = append(all, scanWinget()...)

	return dedupe(all)
}

func IsElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	return token.IsElevated()
}

func extractRegValue(output string) string {
	// Windows reg output format:
	// "    ValueName    REG_TYPE    ActualValue"
	// We need to extract "ActualValue"

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and the key path line
		if line == "" || strings.HasPrefix(line, "HKEY_") {
			continue
		}

		// Split by whitespace and get the last non-empty field
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// Last field is the value
			return fields[len(fields)-1]
		}
	}
	return ""
}

func isEncryptedWindows() bool {
	out, err := exec.Command("manage-bde", "-status", "C:").Output()
	if err != nil {
		return false
	}

	s := strings.ToLower(string(out))

	// key signals
	return strings.Contains(s, "protection on")
}

func IsDiskEncrypted() bool {
	return isEncryptedWindows()
}

func GetProfiler() string {
	cmds := []string{
		"(Get-CimInstance Win32_BIOS).SerialNumber",
		"(Get-CimInstance Win32_ComputerSystemProduct).IdentifyingNumber",
	}

	for _, c := range cmds {
		out, err := exec.Command("powershell", "-Command", c).Output()
		if err == nil {
			s := strings.TrimSpace(string(out))
			if isValidSerial(s) {
				return s
			}
		}
	}

	return "failed to get profiler"
}

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
)

func createJobObject() (syscall.Handle, error) {
	r1, _, err := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		return 0, err
	}
	return syscall.Handle(r1), nil
}

func assignProcessToJob(job syscall.Handle, p *os.Process) error {
	r1, _, err := procAssignProcessToJobObject.Call(
		uintptr(job),
		uintptr(p.Pid),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func RunCommandString(command string, timeout time.Duration, onStream StreamFn) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cmd", "/C", command)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}

	var out bytes.Buffer

	read := func(r io.ReadCloser) {
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				out.Write(chunk)

				if onStream != nil {
					onStream(string(chunk))
				}
			}
			if err != nil {
				return
			}
		}
	}

	go read(stdout)
	go read(stderr)

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return out.String(), err

	case <-ctx.Done():
		// timeout path: kill only the parent process
		_ = cmd.Process.Kill()

		<-waitCh // ensure cleanup
		return out.String(), fmt.Errorf("timeout after %s", timeout)
	}
}

func (c *AuditLogCollector) Stop() {
	return
}

func (c *AuditLogCollector) LogCollectorStart(ctx context.Context) error {
	return errors.New("Not implemented on windows") 
}

func NewAuditLogCollector(config shuffle.TelemetryConfig) (*AuditLogCollector, error) {
	auditLogCollector := AuditLogCollector{}
	return &auditLogCollector, errors.New("Not implemented on windows")
}

func queryRegValue(name string) (string, error) {
	cmd := exec.Command(
		"reg", "query",
		`HKEY_CURRENT_USER\Control Panel\Desktop`,
		"/v", name,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, name) {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[len(fields)-1], nil
			}
		}
	}
	return "", fmt.Errorf("value not found")
}

func IsAutomaticScreenlockEnabled() bool {
	activeStr, err := queryRegValue("ScreenSaveActive")
	if err != nil {
		log.Printf("[ERROR] ScreenSaveActive: %v", err)
		return false
	}

	secureStr, err := queryRegValue("ScreenSaverIsSecure")
	if err != nil {
		log.Printf("[ERROR] ScreenSaverIsSecure: %v", err)
		return false
	}

	timeoutStr, err := queryRegValue("ScreenSaveTimeOut")
	if err != nil {
		log.Printf("[ERROR] ScreenSaveTimeOut: %v", err)
		return false
	}

	active := parseInt(activeStr)
	secure := parseInt(secureStr)
	timeout := parseInt(timeoutStr)

	return active == 1 && secure == 1 && timeout <= 900
}

type osVersionInfoEx struct {
	dwOSVersionInfoSize uint32
	dwMajorVersion      uint32
	dwMinorVersion      uint32
	dwBuildNumber       uint32
	dwPlatformId        uint32
	szCSDVersion        [128]uint16
	wServicePackMajor   uint16
	wServicePackMinor   uint16
	wSuiteMask          uint16
	wProductType        byte
	wReserved           byte
}

const (
	backupFile = "C:\\Windows\\Temp\\firewall_backup_edr.wfw"
)

func isAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

func isolateHostWindows(allowIPs []string) error {
	// Must run as admin
	if !isAdmin() {
		return fmt.Errorf("requires administrator privileges")
	}

	// 1. Backup firewall state
	exec.Command("netsh", "advfirewall", "export", backupFile).Run()

	// 2. Set default block policies
	cmds := [][]string{
		{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"},
	}

	for _, c := range cmds {
		if err := exec.Command(c[0], c[1:]...).Run(); err != nil {
			return fmt.Errorf("failed to set firewall policy: %w", err)
		}
	}

	// 3. Allow loopback explicitly
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=EDR-Allow-Loopback",
		"dir=in",
		"action=allow",
		"interface=any",
		"enable=yes").Run()

	exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=EDR-Allow-Loopback-Out",
		"dir=out",
		"action=allow",
		"interface=any",
		"enable=yes").Run()

	// 4. Allow EDR endpoints
	for _, ip := range allowIPs {
		exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=EDR-Allow-%s", ip),
			"dir=out",
			"action=allow",
			fmt.Sprintf("remoteip=%s", ip),
			"enable=yes").Run()

		exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			fmt.Sprintf("name=EDR-Allow-In-%s", ip),
			"dir=in",
			"action=allow",
			fmt.Sprintf("remoteip=%s", ip),
			"enable=yes").Run()
	}

	return nil
}

func unisolateHostWindows() error {
	if !isAdmin() {
		return fmt.Errorf("requires administrator privileges")
	}

	// Restore firewall config
	return exec.Command("netsh", "advfirewall", "import", backupFile).Run()
}

func isolateHost(allowIPs []string) error {
	return isolateHostWindows(allowIPs)
}

func unisolateHost() error {
	return unisolateHostWindows()
}


// ========================
// Windows API bindings
// ========================

type winRect struct {
	Left, Top, Right, Bottom int32
}

var (
	user32 = windows.NewLazySystemDLL("user32.dll")

	procSetCursorPos             = user32.NewProc("SetCursorPos")
	procMouseEvent               = user32.NewProc("mouse_event")
	procKeybdEvent               = user32.NewProc("keybd_event")
	procGetForegroundWindow      = user32.NewProc("GetForegroundWindow")
	procGetWindowTextW           = user32.NewProc("GetWindowTextW")
	procGetWindowRect            = user32.NewProc("GetWindowRect")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
)

// ========================
// Mouse constants & Flags
// ========================

const (
	MOUSE_LEFTDOWN    = 0x0002
	MOUSE_LEFTUP      = 0x0004
	MOUSE_RIGHTDOWN   = 0x0008
	MOUSE_RIGHTUP     = 0x0010
	KEYEVENTF_KEYUP   = 0x0002
	KEYEVENTF_UNICODE = 0x0004
)

// FetchFocusedElement fetches the currently focused / active foreground window
// on Windows, returning its bounding box, title, and process name.
func FetchFocusedElement(displayNum int, maxDepth int) ([]shuffle.UIElement, error) {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return nil, nil
	}

	var r winRect
	ret, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	if ret == 0 {
		return nil, nil
	}

	buf := make([]uint16, 512)
	lenRet, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 512)
	title := ""
	if lenRet > 0 {
		title = windows.UTF16ToString(buf[:lenRet])
	}

	var pid uint32
	procGetWindowThreadProcessId.Call(hwnd, uintptr(unsafe.Pointer(&pid)))

	appName := "Unknown"
	if pid > 0 {
		if hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
			defer windows.CloseHandle(hProcess)
			nameBuf := make([]uint16, 1024)
			nSize := uint32(len(nameBuf))
			if err := windows.QueryFullProcessImageName(hProcess, 0, &nameBuf[0], &nSize); err == nil {
				appName = filepath.Base(windows.UTF16ToString(nameBuf[:nSize]))
			}
		}
	}

	w := float64(r.Right - r.Left)
	h := float64(r.Bottom - r.Top)
	x := float64(r.Left)
	y := float64(r.Top)

	elem := shuffle.UIElement{
		AppName: appName,
		Role:    "Window",
		Label:   title,
		ClickPoint: shuffle.Point{
			X: x + (w / 2.0),
			Y: y + (h / 2.0),
		},
		Rect: shuffle.Rect{
			X:      x,
			Y:      y,
			Width:  w,
			Height: h,
		},
	}

	return []shuffle.UIElement{elem}, nil
}

// GetDisplaySizeWindows returns the dimensions of every active display.
// Prefer calling Screenshot() if you need both image and size — it is cheaper.
func GetDisplaySizeWindows() ([]shuffle.DisplaySize, error) {
	if err := checkInteractiveSession(); err != nil {
		return nil, err
	}
 
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", `
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Screen]::AllScreens |
    Select-Object @{N='Width';E={$_.Bounds.Width}}, @{N='Height';E={$_.Bounds.Height}} |
    ConvertTo-Json -Compress
`).Output()
	if err != nil {
		return nil, fmt.Errorf("querying displays: %w", err)
	}
 
	trimmed := strings.TrimSpace(string(out))
	if strings.HasPrefix(trimmed, "{") {
		trimmed = "[" + trimmed + "]"
	}
 
	var records []struct {
		Width  int `json:"Width"`
		Height int `json:"Height"`
	}
	if err := json.Unmarshal([]byte(trimmed), &records); err != nil {
		return nil, fmt.Errorf("parsing display sizes: %w", err)
	}
 
	sizes := make([]shuffle.DisplaySize, len(records))
	for i, r := range records {
		sizes[i] = shuffle.DisplaySize{DisplayID: i + 1, Width: r.Width, Height: r.Height}
	}
	return sizes, nil
}
 
// GetCursorPositionWindows returns the current cursor position.
// Origin (0,0) is the top-left of the primary display.
// Prefer calling Screenshot() if you need both image and cursor — it is cheaper.
func GetCursorPositionWindows() (shuffle.Position, error) {
	if err := checkInteractiveSession(); err != nil {
		return shuffle.Position{}, err
	}
 
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", `
Add-Type -AssemblyName System.Windows.Forms
$p = [System.Windows.Forms.Cursor]::Position
Write-Output "$($p.X) $($p.Y)"`).Output()
	if err != nil {
		return shuffle.Position{}, fmt.Errorf("querying cursor position: %w", err)
	}
 
	var x, y float64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%f %f", &x, &y); err != nil {
		return shuffle.Position{}, fmt.Errorf("parsing cursor position %q: %w", out, err)
	}
	return shuffle.Position{X: x, Y: y}, nil
}
 
// checkInteractiveSession returns an error if the process is running in
// Windows Session 0 (the non-interactive service session). Session 0 has no
// display, no cursor, and no desktop — all GUI calls will fail or hang there.
func checkInteractiveSession() error {
	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command",
		`(Get-Process -Id $PID).SessionId`,
	).Output()
	if err != nil {
		// Can't determine session — proceed and let the caller handle failure.
		return nil
	}
	var id int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &id); err != nil {
		return nil
	}
	if id == 0 {
		return fmt.Errorf("running in Session 0 (non-interactive service session) — no display available")
	}
	return nil
}

// ========================
// RemoteControl methods
// ========================

func remoteControlBatch(batch shuffle.RemoteControlActionBatch) error {
	for _, a := range batch.Actions {
		remoteControlExecute(a)
	}

	return nil
}

func remoteControlExecute(a shuffle.RemoteControl) {
	switch a.Op {

	// -------- Mouse --------

	case "mouse.move":
		x := getInt(a.Params, "x")
		y := getInt(a.Params, "y")
		setCursor(x, y)

	case "mouse.click":
		x := getInt(a.Params, "x")
		y := getInt(a.Params, "y")
		button := getString(a.Params, "button")
		delay := getInt(a.Params, "delay_ms")

		setCursor(x, y)
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}

		mouseDown(button)
		time.Sleep(50 * time.Millisecond)
		mouseUp(button)

	case "mouse.drag":
		fx := getInt(a.Params, "from_x")
		fy := getInt(a.Params, "from_y")
		tx := getInt(a.Params, "to_x")
		ty := getInt(a.Params, "to_y")
		button := getString(a.Params, "button")

		setCursor(fx, fy)
		time.Sleep(50 * time.Millisecond)

		mouseDown(button)
		time.Sleep(50 * time.Millisecond)

		setCursor(tx, ty)
		time.Sleep(50 * time.Millisecond)

		mouseUp(button)

	// -------- Keyboard --------

	case "keyboard.press":
		vk := uint16(getInt(a.Params, "key"))
		if vk == 0 {
			if kName := getString(a.Params, "key_name"); kName != "" {
				if code, ok := keyNameToVK[strings.ToLower(kName)]; ok {
					vk = code
				}
			}
		}
		if vk == 0 {
			if kStr := getString(a.Params, "key"); kStr != "" {
				if code, ok := keyNameToVK[strings.ToLower(kStr)]; ok {
					vk = code
				}
			}
		}
		if vk != 0 {
			keyPress(vk)
		}

	case "keyboard.type":
		text := extractString(a.Params["text"])
		if text == "" {
			text = getString(a.Params, "text")
		}
		if text != "" {
			for _, r := range text {
				procKeybdEvent.Call(0, uintptr(r), KEYEVENTF_UNICODE, 0)
				time.Sleep(5 * time.Millisecond)
				procKeybdEvent.Call(0, uintptr(r), KEYEVENTF_UNICODE|KEYEVENTF_KEYUP, 0)
				time.Sleep(15 * time.Millisecond)
			}
		}

	case "keyboard.hotkey":
		keySlice := parseHotkeyParams(a.Params["keys"])
		if len(keySlice) == 0 {
			keySlice = extractStringSlice(a.Params["keys"])
		}
		if len(keySlice) == 0 {
			keySlice = parseHotkeyParams(a.Params["key"])
		}

		var vks []uint16
		for _, k := range keySlice {
			if code, ok := keyNameToVK[strings.ToLower(strings.TrimSpace(k))]; ok {
				vks = append(vks, code)
			}
		}

		if len(vks) > 0 {
			for _, vk := range vks {
				procKeybdEvent.Call(uintptr(vk), 0, 0, 0)
				time.Sleep(15 * time.Millisecond)
			}
			time.Sleep(30 * time.Millisecond)
			for i := len(vks) - 1; i >= 0; i-- {
				procKeybdEvent.Call(uintptr(vks[i]), 0, KEYEVENTF_KEYUP, 0)
				time.Sleep(15 * time.Millisecond)
			}
		}

	// -------- Utility --------

	case "system.wait":
		ms := getInt(a.Params, "ms")
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}

// ========================
// Windows input functions
// ========================

func setCursor(x, y int) {
	procSetCursorPos.Call(uintptr(x), uintptr(y))
}

func mouseDown(button string) {
	if button == "right" {
		procMouseEvent.Call(MOUSE_RIGHTDOWN, 0, 0, 0, 0)
		return
	}
	procMouseEvent.Call(MOUSE_LEFTDOWN, 0, 0, 0, 0)
}

func mouseUp(button string) {
	if button == "right" {
		procMouseEvent.Call(MOUSE_RIGHTUP, 0, 0, 0, 0)
		return
	}
	procMouseEvent.Call(MOUSE_LEFTUP, 0, 0, 0, 0)
}

func keyPress(vk uint16) {
	procKeybdEvent.Call(uintptr(vk), 0, 0, 0)
	time.Sleep(30 * time.Millisecond)
	procKeybdEvent.Call(uintptr(vk), 0, KEYEVENTF_KEYUP, 0)
}

func Screenshot() ([]shuffle.ScreenshotWrapper, error) {
	if err := checkInteractiveSession(); err != nil {
		return nil, err
	}
 
	// We need per-display images, so we capture each screen individually
	// and collect metadata for all of them in one PowerShell call.
	tmpDir := os.TempDir()
	ts := time.Now().UnixNano()
 
	// The script does three things:
	//   1. Captures each Screen individually to a temp file named by index.
	//   2. Reads cursor position.
	//   3. Emits a JSON array describing each screen (dimensions, cursor,
	//      temp file path) so Go can read it back without more parsing.
	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
 
$cursor = [System.Windows.Forms.Cursor]::Position
$screens = [System.Windows.Forms.Screen]::AllScreens
$results = @()
 
for ($i = 0; $i -lt $screens.Length; $i++) {
    $s    = $screens[$i]
    $path = "%s\edr-%d-d$i.png"
 
    $bmp = New-Object System.Drawing.Bitmap($s.Bounds.Width, $s.Bounds.Height)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $gfx.CopyFromScreen($s.Bounds.Left, $s.Bounds.Top, 0, 0, $bmp.Size)
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $gfx.Dispose()
    $bmp.Dispose()
 
    $results += [PSCustomObject]@{
        Path    = $path
        Width   = $s.Bounds.Width
        Height  = $s.Bounds.Height
        CursorX = $cursor.X
        CursorY = $cursor.Y
    }
}
 
$results | ConvertTo-Json -Compress
`, tmpDir, ts)
 
	command := exec.Command(
		"powershell", "-WindowStyle", "Hidden", "-NoProfile", "-NonInteractive", "-Command", script,
	)

	command.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:     true,
		CreationFlags:   0x08000000, // CREATE_NO_WINDOW
	}

	out, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("screenshot script failed: %w", err)
	}
 
	// PowerShell emits a bare object (not array) when there is exactly one
	// screen. Normalise to array so json.Unmarshal always gets a slice.
	trimmed := strings.TrimSpace(string(out))
	if strings.HasPrefix(trimmed, "{") {
		trimmed = "[" + trimmed + "]"
	}
 
	var records []struct {
		Path    string  `json:"Path"`
		Width   int     `json:"Width"`
		Height  int     `json:"Height"`
		CursorX float64 `json:"CursorX"`
		CursorY float64 `json:"CursorY"`
	}
	if err := json.Unmarshal([]byte(trimmed), &records); err != nil {
		return nil, fmt.Errorf("parsing screenshot metadata: %w", err)
	}
 
	wrappers := make([]shuffle.ScreenshotWrapper, 0, len(records))
	for i, r := range records {
		data, err := os.ReadFile(r.Path)
		os.Remove(r.Path) // clean up regardless of read outcome
		if err != nil {
			return nil, fmt.Errorf("reading screenshot for display %d: %w", i, err)
		}

		elementTree, err := FetchFocusedElement(i+1, 10)
		if err != nil {
			log.Printf("[ERROR] Focused tree problem for screen %d: %v", i+1, err)
		}

		screen := shuffle.ScreenshotWrapper{
			Image:       data,
			ScreenSize:  shuffle.DisplaySize{DisplayID: i + 1, Width: r.Width, Height: r.Height},
			Cursor:      shuffle.Position{X: r.CursorX, Y: r.CursorY},
			ElementTree: elementTree,
		}

		wrappers = append(wrappers, screen)
	}
	return wrappers, nil
}

// CheckAccessibilityTrusted returns true on Windows (not governed by macOS TCC).
func CheckAccessibilityTrusted() bool {
	return true
}

// PromptAccessibility is a no-op on Windows.
func PromptAccessibility() {}

// CheckScreenRecordingPermission returns true on Windows.
func CheckScreenRecordingPermission() bool {
	return true
}

// PromptScreenRecording is a no-op on Windows.
func PromptScreenRecording() {}

