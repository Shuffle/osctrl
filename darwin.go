//go:build darwin

package osctrl 

/*
#cgo LDFLAGS: -framework ApplicationServices -framework CoreFoundation

#include <ApplicationServices/ApplicationServices.h>

static int GetNativeCursorPosition(double *x, double *y) {
    CGEventRef event = CGEventCreate(NULL);
    if (event == NULL) {
        return 0;
    }
    CGPoint point = CGEventGetLocation(event);
    *x = point.x;
    *y = point.y;
    CFRelease(event);
    return 1;
}

// Warp the cursor position natively
static void NativeSetCursor(double x, double y) {
    CGPoint pt = CGPointMake(x, y);
    CGWarpMouseCursorPosition(pt);
    CGAssociateMouseAndMouseCursorPosition(true);
}

// Fetch current cursor location for posting relative down/up events
static CGPoint GetCurrentPoint() {
    CGEventRef event = CGEventCreate(NULL);
    CGPoint pt = CGPointMake(0, 0);
    if (event != NULL) {
        pt = CGEventGetLocation(event);
        CFRelease(event);
    }
    return pt;
}

// Post mouse button down/up events using primitive types
static void NativeMouseEvent(uint32_t type, uint32_t button) {
    CGPoint pt = GetCurrentPoint();
    CGEventRef event = CGEventCreateMouseEvent(
        NULL,
        (CGEventType)type,
        pt,
        (CGMouseButton)button
    );
    if (event != NULL) {
        CGEventPost(kCGHIDEventTap, event);
        CFRelease(event);
    }
}

// Post keyboard press down/up events
static void NativeKeyEvent(CGKeyCode keycode, bool keyDown) {
    CGEventRef event = CGEventCreateKeyboardEvent(NULL, keycode, keyDown);
    if (event != NULL) {
        CGEventPost(kCGHIDEventTap, event);
        CFRelease(event);
    }
}
*/
import "C"
import (
	"github.com/shuffle/shuffle-shared"
	"os"
	"time"
	"fmt"
	"strings"
	"errors"
	"log"
	"encoding/json"
	"path/filepath"

	"os/exec"
	"runtime"
	"bytes"
	"strconv"
)

var debug bool = os.Getenv("DEBUG") == "1"

// GetCursorPositionMacos returns the current cursor position in global screen
// coordinates using native macOS CoreGraphics. The origin (0,0) is the top-left of the
// primary display; coordinates increase right and down.
func GetCursorPositionMacos() (shuffle.Position, error) {
	var x, y C.double
	if ok := C.GetNativeCursorPosition(&x, &y); ok == 0 {
		return shuffle.Position{}, fmt.Errorf("failed to retrieve cursor position via CoreGraphics")
	}

	return shuffle.Position{
		X: float64(x),
		Y: float64(y),
	}, nil
}

//func remoteControlBatch(batch shuffle.RemoteControlActionBatch) error {
//	return errors.New(fmt.Sprintf("remote control not implemented for %s. Verified for Windows only.", runtime.GOOS))
//}


func remoteControlBatch(batch shuffle.RemoteControlActionBatch) error {
	for _, a := range batch.Actions {
		remoteControlExecute(a)
	}

	return nil
}

const (
	anchorName   = "edr_isolation"
	anchorFile   = "/etc/pf.anchors/edr_isolation"
	pfConf       = "/etc/pf.conf"
	pfConfBackup = "/etc/pf.conf.backup_edr"

	nftConf       = "/etc/nftables.conf"
	nftBackup     = "/etc/nftables.conf.backup_edr"
	isolationFile = "/etc/nftables.edr.conf"
)

func isolateHostMacos(allowIPs []string) error {
	if os.Geteuid() != 0 {
		return errors.New(fmt.Sprintf("must run as root"))
	}

	// 1. Backup pf.conf once
	if _, err := os.Stat(pfConfBackup); os.IsNotExist(err) {
		input, err := os.ReadFile(pfConf)
		if err != nil {
			return err
		}
		if err := os.WriteFile(pfConfBackup, input, 0600); err != nil {
			return err
		}
	}

	// 2. Build anchor rules
	var rules strings.Builder

	rules.WriteString("block all\n")
	rules.WriteString("pass quick on lo0 all\n")

	for _, ip := range allowIPs {
		rules.WriteString(fmt.Sprintf("pass out quick to %s keep state\n", ip))
		rules.WriteString(fmt.Sprintf("pass in quick from %s keep state\n", ip))
	}

	if err := os.WriteFile(anchorFile, []byte(rules.String()), 0600); err != nil {
		return err
	}

	// 3. Ensure pf.conf loads our anchor
	confData, err := os.ReadFile(pfConf)
	if err != nil {
		return err
	}

	confStr := string(confData)

	anchorLine := fmt.Sprintf("anchor \"%s\"\nload anchor \"%s\" from \"%s\"\n", anchorName, anchorName, anchorFile)

	if !strings.Contains(confStr, anchorName) {
		confStr += "\n" + anchorLine
		if err := os.WriteFile(pfConf, []byte(confStr), 0644); err != nil {
			return err
		}
	}

	// 4. Enable PF
	exec.Command("pfctl", "-E").Run()

	// 5. Load full config (which includes anchor)
	if err := exec.Command("pfctl", "-f", pfConf).Run(); err != nil {
		return err
	}

	return nil
}

func unisolateHostMacos() error {
	if os.Geteuid() != 0 {
		return errors.New(fmt.Sprintf("must run as root"))
	}

	// pfConfBackup = "/etc/pf.conf.backup_edr"
	// Restore original pf.conf
	backup, err := os.ReadFile(pfConfBackup)
	if err != nil {
		return err
	}

	if err := os.WriteFile(pfConf, backup, 0644); err != nil {
		return err
	}

	// Reload PF config
	if err := exec.Command("pfctl", "-f", pfConf).Run(); err != nil {
		return err
	}

	return nil
}

func isolateHost(allowIPs []string) error {
	if runtime.GOOS == "darwin" {
		return isolateHostMacos(allowIPs)
	}

	return errors.New(fmt.Sprintf("isolation not supported on this platform"))
}

func unisolateHost() error {
	if runtime.GOOS == "darwin" {
		return unisolateHostMacos()
	}

	return errors.New(fmt.Sprintf("un-isolation not supported on this platform"))
}

func setCursor(x, y int) {
	C.NativeSetCursor(C.double(x), C.double(y))
}

func mouseDown(button string) {
	btn := C.kCGMouseButtonLeft
	evtType := C.kCGEventLeftMouseDown

	if button == "right" {
		btn = C.kCGMouseButtonRight
		evtType = C.kCGEventRightMouseDown
	}

	C.NativeMouseEvent(C.uint32_t(evtType), C.uint32_t(btn))
}

func mouseUp(button string) {
	btn := C.kCGMouseButtonLeft
	evtType := C.CGEventType(C.kCGEventLeftMouseUp)

	if button == "right" {
		btn = C.kCGMouseButtonRight
		evtType = C.CGEventType(C.kCGEventRightMouseUp)
	}

	C.NativeMouseEvent(C.uint32_t(evtType), C.uint32_t(btn))
}

// vkToMacKeyCode maps Windows Virtual Key (VK) / ASCII codes to macOS CGKeyCodes.
var vkToMacKeyCode = map[uint16]C.CGKeyCode{
	// Letters (A-Z / ASCII 65-90)
	65: 0,  // A
	66: 11, // B
	67: 8,  // C
	68: 2,  // D
	69: 14, // E
	70: 3,  // F
	71: 5,  // G
	72: 4,  // H
	73: 34, // I
	74: 38, // J
	75: 40, // K
	76: 37, // L
	77: 46, // M
	78: 45, // N
	79: 31, // O
	80: 35, // P
	81: 12, // Q
	82: 15, // R
	83: 1,  // S
	84: 17, // T
	85: 32, // U
	86: 9,  // V
	87: 13, // W
	88: 7,  // X
	89: 16, // Y
	90: 6,  // Z

	// Numbers (0-9 / ASCII 48-57)
	48: 29, // 0
	49: 18, // 1
	50: 19, // 2
	51: 20, // 3
	52: 21, // 4
	53: 23, // 5
	54: 22, // 6
	55: 26, // 7
	56: 28, // 8
	57: 25, // 9

	// Common Control Keys
	8:  51, // Backspace / Delete
	9:  48, // Tab
	13: 36, // Return / Enter
	27: 53, // Escape
	32: 49, // Space
	37: 123, // Left Arrow
	38: 126, // Up Arrow
	39: 124, // Right Arrow
	40: 125, // Down Arrow
}

func Screenshot() ([]shuffle.ScreenshotWrapper, error) {
	return ScreenshotMacos()
}

func ScreenshotMacos() ([]shuffle.ScreenshotWrapper, error) {
	screens, err := ScreenshotAllDisplaysMacos()
	if err != nil {
		return nil, err
	}

	if len(screens) == 0 {
		return nil, errors.New(fmt.Sprintf("no displays captured"))
	}

	return screens, nil
}

// GetDisplaySizeMacos returns the width and height of every active display.
// Uses system_profiler SPDisplaysDataType — no cgo, no extra tools required.
func getDisplaySizeMacos() ([]shuffle.DisplaySize, error) {
	out, err := exec.Command(
		"system_profiler", "SPDisplaysDataType", "-json",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("system_profiler failed: %w", err)
	}

	// Parse just enough of the JSON to extract resolution strings.
	// Format: "Resolution: 2560 x 1600 Retina"
	var result struct {
		SPDisplaysDataType []struct {
			Displays []struct {
				Resolution string `json:"_spdisplays_resolution"`
			} `json:"spdisplays_ndrvs"`
		} `json:"SPDisplaysDataType"`
	}

	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parsing display info: %w", err)
	}

	var sizes []shuffle.DisplaySize
	for _, gpu := range result.SPDisplaysDataType {
		for i, d := range gpu.Displays {
			var w, h int
			// Resolution string is "2560 x 1600 Retina" or "2560 x 1600"
			fmt.Sscanf(d.Resolution, "%d x %d", &w, &h)
			if w == 0 || h == 0 {
				continue
			}
			sizes = append(sizes, shuffle.DisplaySize{
				DisplayID: i + 1,
				Width:     w,
				Height:    h,
			})
		}
	}

	if len(sizes) == 0 {
		return nil, fmt.Errorf("no display resolution data found")
	}
	return sizes, nil
}

func GetFrontmostPIDShell() (int, error) {
	script := `tell application "System Events" to get unix id of first application process whose frontmost is true`
	cmd := exec.Command("osascript", "-e", script)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return 0, err
	}

	pidStr := strings.TrimSpace(out.String())
	return strconv.Atoi(pidStr)
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
	cmd := exec.Command("screencapture", "-x", "-t", "jpg", "-D", fmt.Sprintf("%d", display), path)
	//cmd := exec.Command("screencapture", "-x", "-t", "png", "-D", fmt.Sprintf("%d", display), fmt.Sprintf("fullsize-%s", path), "&&", "sips", "-resampleHeightWidthMax", "1280", fmt.Sprintf("fullsize-%s", path), "--out", path)
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

// ScreenshotAllDisplays captures every active display and returns one PNG
// per display. Display indices are 1-based in screencapture; we probe until
// the tool produces no output, which is how it signals an out-of-range index.
func ScreenshotAllDisplaysMacos() ([]shuffle.ScreenshotWrapper, error) {
	var screens []shuffle.ScreenshotWrapper

	cursorPosition, err := GetCursorPositionMacos()
	if err != nil {
		log.Printf("[WARN] Unable to get cursor position: %v\n", err)
	}

	screenSizes, err := getDisplaySizeMacos()
	if err != nil {
		log.Printf("[WARN] Unable to get display sizes: %v\n", err)
	}

	/*
	elementTree := make([]*C.AXUIElementRef, 0)
	targetPID, err := GetFrontmostPIDShell()
	if err != nil {
		log.Printf("[WARN] Unable to get frontmost PID: %v\n", err)
	} else {
		appRef := C.AXUIElementCreateApplication(C.pid_t(targetPID))
		defer C.CFRelease(C.CFTypeRef(appRef))
		elementTree, err = traverseAXTree(appRef)
		if err != nil {
			log.Printf("[WARN] Unable to traverse AX tree: %v\n", err)
		}
	}
	*/

	for display := 1; ; display++ {
		img, err := captureDisplay(display)
		if err != nil {
			// First display failing is a real error (permission, no display).
			if display == 1 {
				return nil, err
			}

			break
		}


		screens = append(screens, shuffle.ScreenshotWrapper{
			Image: img,
			Cursor: cursorPosition,
			//ElementTree: elementTree,
		})

		if len(screenSizes) >= display {
			screens[len(screens)-1].ScreenSize.Width = screenSizes[display-1].Width
			screens[len(screens)-1].ScreenSize.Height = screenSizes[display-1].Height
		}

		// Just doing a single screen
		if debug { 
			log.Printf("[DEBUG] Captured display %d, size: %dx%d\n", display, screens[len(screens)-1].ScreenSize.Width, screens[len(screens)-1].ScreenSize.Height)
		}

		//break
	}

	return screens, nil
}

// Node mirrors the CDP AXNode concept mapped to macOS native fields
/*
type AXNode struct {
	ID       string    `json:"nodeId"`
	Role     string    `json:"role"`
	Title    string    `json:"title,omitempty"`
	Children []AXNode  `json:"children,omitempty"`
}

func traverseAXTree(element C.AXUIElementRef) AXNode {
	node := AXNode{}

	// 1. Get Role
	roleCF := C.copy_string_attribute(element, C.kAXRoleAttribute)
	if roleCF != 0 {
		node.Role = GoStringFromCFString(roleCF)
		C.CFRelease(C.CFTypeRef(roleCF))
	}

	// 2. Get Title
	titleCF := C.copy_string_attribute(element, C.kAXTitleAttribute)
	if titleCF != 0 {
		node.Title = GoStringFromCFString(titleCF)
		C.CFRelease(C.CFTypeRef(titleCF))
	}

	// 3. Get Children
	var childrenRef C.CFTypeRef
	if C.AXUIElementCopyAttributeValue(element, C.kAXChildrenAttribute, &childrenRef) == C.kAXErrorSuccess {
		if C.CFGetTypeID(childrenRef) == C.CFArrayGetTypeID() {
			array := C.CFArrayRef(childrenRef)
			count := C.CFArrayGetCount(array)
			for i := C.CFIndex(0); i < count; i++ {
				child := C.AXUIElementRef(C.CFArrayGetValueAtIndex(array, i))
				node.Children = append(node.Children, traverseAXTree(child))
			}
		}
		C.CFRelease(childrenRef)
	}

	return node
}
*/

func GetProfiler() string {
	return getProfileMac()
}

func getProfileMac() string {
	out, err := exec.Command("system_profiler", "SPHardwareDataType").Output()
	if err == nil { 
		return string(out)
	}

	return "failed to locate (macos)"
}

func ListInstalledSoftware() []shuffle.Software {
	systemInfo := FindSystemVersionMacOS()
	systemApps := listMacSoftware()
	homebrew := listBrew()

	allSoftware := []shuffle.Software{systemInfo}
	allSoftware = append(allSoftware, systemApps...)
	allSoftware = append(allSoftware, homebrew...)
	return allSoftware
}

func FindSystemVersionMacOS() shuffle.Software {
	get := func(flag string) (string, error) {
	out, err := exec.Command("sw_vers", flag).Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}

	productName, err := get("-productName")
	if err != nil {
		return shuffle.Software{}
	}

	version, err := get("-productVersion")
	if err != nil {
		return shuffle.Software{}
	}

	build, err := get("-buildVersion")
	if err != nil {
		return shuffle.Software{}
	}

	return shuffle.Software{
		Name:    fmt.Sprintf("%s %s (%s)", productName, version, build),
		Version: version,
	}
}

func listMacSoftware() []shuffle.Software {
	out, err := exec.Command(
		"system_profiler",
		"SPApplicationsDataType",
		"-json",
	).Output()

	if err != nil {
		return nil
	}

	var p macProfile
	if err := json.Unmarshal(out, &p); err != nil {
		return nil
	}

	result := make([]shuffle.Software, 0, len(p.Apps))
	for _, app := range p.Apps {
		version := app.Version
		if version == "" {
			version = app.BundleVersion
		}

		if version == "" {
			version = app.Info
		}

		result = append(result, shuffle.Software{
			Name:    app.Name,
			Version: version,
		})
	}

	return result
}

func listBrew() []shuffle.Software {
	out, err := exec.Command("brew", "list", "--versions").Output()
	if err != nil {
		return nil
	}

	var result []shuffle.Software

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result = append(result, shuffle.Software{
				Name:    fields[0],
				Version: fields[1],
			})
		}
	}

	return result
}

type macProfile struct {
	Apps []MacApp `json:"SPApplicationsDataType"`
}

func IsAutomaticScreenlockEnabled() bool { 
	return willLockWithin15MinMac()
}

func willLockWithin15MinMac() bool {
	idleSec := getMacIdleTimeSeconds()
	if idleSec <= 0 {
		return false
	}

	lockEnabled := isMacScreenLockEnabled()

	// must both be true
	//return lockEnabled && idleSec <= 900
	return lockEnabled && idleSec <= 10800 
}

func getMacIdleTimeSeconds() int {
	// try currentHost (more reliable than system-wide)
	out, err := exec.Command(
		"defaults",
		"-currentHost",
		"read",
		"com.apple.screensaver",
		"idleTime",
	).Output()

	if err == nil {
		if v := parseInt(strings.TrimSpace(string(out))); v > 0 {
			return v
		}
	}

	// fallback: system-wide pmset
	out, err = exec.Command("pmset", "-g", "custom").Output()
	if err == nil {
		return parsePmsetDisplaySleep(out)
	}

	return 0
}

func parsePmsetDisplaySleep(out []byte) int {
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "displaysleep") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				mins := parseInt(fields[1])
				return mins * 60
			}
		}
	}

	return 0
}

func isMacScreenLockEnabled() bool {
	out, err := exec.Command(
		"defaults",
		"read",
		"com.apple.screensaver",
		"askForPassword",
	).Output()

	if err != nil {
		// missing key → assume enabled in managed/security contexts
		return true
	}

	return strings.TrimSpace(string(out)) == "1"
}

func IsDiskEncryptedMacos() (bool, error) {
	cmd := exec.Command("/usr/bin/fdesetup", "status")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("failed to run fdesetup: %w", err)
	}

	status := strings.TrimSpace(out.String())
	// "FileVault is On."
	if strings.HasPrefix(status, "FileVault is On") {
		return true, nil
	}

	return false, nil
}

func IsDiskEncrypted() bool {
	result, err := IsDiskEncryptedMacos()
	if err != nil {
		log.Printf("[ERROR] Error checking disk encryption: %v", err)
		return result 
	}

	return result
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
		time.Sleep(time.Duration(delay) * time.Millisecond)

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
		//key := getInt(a.Params, "key")
		//keyPress(uint16(key))
		keys := parseKeys(a.Params["key"])
		keyPress(keys...)

	// -------- Utility --------

	case "system.wait":
		ms := getInt(a.Params, "ms")
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}

/*
func keyPress(vk uint16) {
	macCode, ok := vkToMacKeyCode[vk]
	if !ok {
		// Fallback: If code is not in the map, pass directly
		macCode = C.CGKeyCode(vk)
	}

	C.NativeKeyEvent(macCode, true)
	time.Sleep(30 * time.Millisecond)
	C.NativeKeyEvent(macCode, false)
}
*/

func parseKeys(param interface{}) []uint16 {
	switch v := param.(type) {

	// Single keycode passed as a number
	case float64: // JSON numbers unmarshal into float64
		return []uint16{uint16(v)}
	case int:
		return []uint16{uint16(v)}

	// String shortcut passed (e.g. "Control+Tab")
	case string:
		return parseShortcutString(v)

	// Array of keycodes passed (e.g. [59, 48])
	case []interface{}:
		var keys []uint16
		for _, item := range v {
			if num, ok := item.(float64); ok {
				keys = append(keys, uint16(num))
			}
		}
		return keys
	}

	return nil
}

func parseShortcutString(shortcut string) []uint16 {
	parts := strings.Split(shortcut, "+")
	vks := make([]uint16, 0, len(parts))

	for _, p := range parts {
		clean := strings.ToLower(strings.TrimSpace(p))
		if vk, ok := keyNameToVK[clean]; ok {
			vks = append(vks, vk)
		}
	}
	return vks
}

func keyDown(vk uint16) {
	macCode, ok := vkToMacKeyCode[vk]
	if !ok {
		macCode = C.CGKeyCode(vk)
	}
	C.NativeKeyEvent(macCode, true)
}

func keyUp(vk uint16) {
	macCode, ok := vkToMacKeyCode[vk]
	if !ok {
		macCode = C.CGKeyCode(vk)
	}
	C.NativeKeyEvent(macCode, false)
}

// keyPress now handles single or multiple key codes
func keyPress(vks ...uint16) {
	if len(vks) == 0 {
		return
	}

	// 1. Press all keys down in order
	for _, vk := range vks {
		keyDown(vk)
		time.Sleep(15 * time.Millisecond)
	}

	time.Sleep(30 * time.Millisecond)

	// 2. Release all keys in REVERSE order
	for i := len(vks) - 1; i >= 0; i-- {
		keyUp(vks[i])
		time.Sleep(15 * time.Millisecond)
	}
}
