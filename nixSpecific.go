//go:build !windows && !darwin

package osctrl 

import (
	"os"
	"os/exec"
	"strings"
	"strconv"
	"regexp"
	"encoding/json"
	"time"
	"context"
	"bytes"
	"io"
	"fmt"
	"log"
	"bufio"
	"path/filepath"
	"errors"

	"syscall"
	"runtime"
	"github.com/shuffle/shuffle-shared"
)

func getAutoLockTimeout() int {
	out, err := exec.Command(
		"gsettings",
		"get",
		"org.gnome.desktop.session",
		"idle-delay",
	).Output()

	if err == nil {
		s := strings.TrimSpace(string(out))
		s = strings.Trim(s, "uint32()")

		if v, err := strconv.Atoi(s); err == nil {
			return v / 60
		}
	}

	return tryKDETimeout()
}

func tryKDETimeout() int {
	data, err := os.ReadFile(os.ExpandEnv("$HOME/.config/kscreenlockerrc"))
	if err != nil {
		return -1
	}

	re := regexp.MustCompile(`Timeout=(\d+)`)
	m := re.FindSubmatch(data)
	if len(m) != 2 {
		return -1
	}

	v, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return -1
	}

	return v
}

func getDesktop() string {
	// most reliable first
	v := os.Getenv("XDG_CURRENT_DESKTOP")
	if v != "" {
		return strings.ToLower(v)
	}

	v = os.Getenv("DESKTOP_SESSION")
	if v != "" {
		return strings.ToLower(v)
	}

	v = os.Getenv("GDMSESSION")
	return strings.ToLower(v)
}

func isGNOME() bool {
	d := getDesktop()
	return strings.Contains(d, "gnome")
}

func isKDE() bool {
	d := getDesktop()
	return strings.Contains(d, "kde") ||
		strings.Contains(d, "plasma")
}

func getAutoLockTimeoutNix() int {
	switch {
	case isGNOME():
		return getAutoLockTimeout()

	case isKDE():
		return tryKDETimeout()

	default:
		return getAutoLockTimeout()
	}
}

func getScreenPolicyUnix() bool { 
	// 15 minutes check
	lockTimeout := getAutoLockTimeoutNix()
	if lockTimeout > 0 && lockTimeout <= 15 {
		return true
	}

	return false
}

func IsAutomaticScreenlockEnabled() bool { 
	switch runtime.GOOS {
	case "windows":
		return false
	case "darwin":
		return willLockWithin15MinMac()
	default: // linux, macOS, etc.
		return getScreenPolicyUnix()
	}
}

func isEncryptedMac() bool {
	out, err := exec.Command("fdesetup", "status").Output()
	if err != nil {
		return false
	}

	s := strings.ToLower(string(out))
	return strings.Contains(s, "filevault is on")
}

func isEncryptedLinux() bool {
	out, err := exec.Command("lsblk", "-o", "NAME,TYPE").Output()
	if err != nil {
		return false
	}

	s := string(out)

	// look for crypt mapping (LUKS/dm-crypt)
	return strings.Contains(s, "crypt")
}

func IsDiskEncrypted() bool {
	switch runtime.GOOS {
	case "windows":
		return false
	case "darwin":
		return false
	default:
		return isEncryptedLinux()
	}
}

func cleanSerial(s string) string {
	return strings.TrimSpace(s)
}

func getSerialLinux() string {
	paths := []string{
		"/sys/class/dmi/id/product_serial",
		"/sys/class/dmi/id/board_serial",
	}

	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			s := cleanSerial(string(data))
			if isValidSerial(s) {
				return s
			}
		}
	}

	// fallback (requires root on many systems)
	out, err := exec.Command("dmidecode", "-s", "system-serial-number").Output()
	if err == nil {
		s := cleanSerial(string(out))
		if isValidSerial(s) {
			return s
		}
	}

	return "failed to locate"
}

func GetProfiler() string {
	switch runtime.GOOS {
	case "windows":
		return ""
	case "darwin":
		return getProfileMac()
	default:
		return getSerialLinux()
	}
}

func listRPM() []shuffle.Software {
	out, err := exec.Command(
		"rpm",
		"-qa",
		"--queryformat",
		"%{NAME} %{VERSION}-%{RELEASE}\n",
	).Output()

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

func listDpkg() []shuffle.Software {
	out, err := exec.Command(
		"dpkg-query",
		"-W",
		"-f=${Package} ${Version}\n",
	).Output()

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

func listPacman() []shuffle.Software {
	out, err := exec.Command(
		"pacman",
		"-Q",
	).Output()

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

func listYay() []shuffle.Software {
	out, err := exec.Command(
		"yay",
		"-Q",
	).Output()

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

func listAPK() []shuffle.Software {
	out, err := exec.Command(
		"apk",
		"info",
		"-v",
	).Output()

	if err != nil {
		return nil
	}

	var result []shuffle.Software

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// split on last "-" because names can contain hyphens
		i := strings.LastIndex(line, "-")
		if i <= 0 || i == len(line)-1 {
			continue
		}

		result = append(result, shuffle.Software{
			Name:    line[:i],
			Version: line[i+1:],
		})
	}

	return result
}

func listLinuxSoftware() []shuffle.Software {
	// dpkg (Debian/Ubuntu)
	found := []shuffle.Software{}
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		found = listDpkg()
		if len(found) > 0 { 
			return found
		}
	}

	// rpm (RHEL/Fedora)
	if _, err := exec.LookPath("rpm"); err == nil {
		found = listRPM()
		if len(found) > 0 { 
			return found
		}
	}

	if _, err := exec.LookPath("pacman"); err == nil {
		found = listPacman() 
		if len(found) > 0 { 
			return found
		}
	}

	if _, err := exec.LookPath("yay"); err == nil {
		found = listYay() 
		if len(found) > 0 { 
			return found
		}
	}

	if _, err := exec.LookPath("apk"); err == nil {
		found = listAPK() 
		if len(found) > 0 { 
			return found
		}
	}

	// fallback
	return []shuffle.Software{}
}

func GetLinuxSoftware() (shuffle.Software, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return shuffle.Software{}, err
	}
	defer file.Close()

	var name, version, codename string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := strings.Trim(parts[1], `"`)

		switch key {
		case "NAME":
			name = value
		case "VERSION_ID":
			version = value
		case "VERSION_CODENAME":
			codename = value
		}
	}

	if err := scanner.Err(); err != nil {
		return shuffle.Software{}, err
	}

	fullName := name
	if version != "" {
		fullName = fmt.Sprintf("%s %s", name, version)
	}
	if codename != "" {
		fullName = fmt.Sprintf("%s (%s)", fullName, codename)
	}

	return shuffle.Software{
		Name:    fullName,
		Version: version,
	}, nil
}

func ListInstalledSoftware() []shuffle.Software {
	allSoftware := []shuffle.Software{}
	defaultSoftware, err := GetLinuxSoftware() 
	if err != nil { 
		log.Printf("[WARNING] Failed to get Linux distribution info: %v", err)
	} else {
		allSoftware = append(allSoftware, defaultSoftware)
	}

	return append(allSoftware, listLinuxSoftware()...)
}

func isolateHostLinux(allowIPs []string) error {
	if os.Geteuid() != 0 {
		return errors.New(fmt.Sprintf("must run as root"))
	}

	// 1. Backup nftables config once
	if _, err := os.Stat(nftBackup); os.IsNotExist(err) {
		data, err := os.ReadFile(nftConf)
		if err != nil {
			return err
		}
		if err := os.WriteFile(nftBackup, data, 0600); err != nil {
			return err
		}
	}

	// 2. Build isolation rules
	var b strings.Builder

	b.WriteString("table inet edr_isolation {\n")

	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority 0;\n")
	b.WriteString("    policy drop;\n")

	// loopback always allowed
	b.WriteString("    iif lo accept\n")

	for _, ip := range allowIPs {
		b.WriteString(fmt.Sprintf("    ip saddr %s accept\n", ip))
	}

	b.WriteString("  }\n")

	b.WriteString("  chain output {\n")
	b.WriteString("    type filter hook output priority 0;\n")
	b.WriteString("    policy drop;\n")

	b.WriteString("    oif lo accept\n")

	for _, ip := range allowIPs {
		b.WriteString(fmt.Sprintf("    ip daddr %s accept\n", ip))
	}

	b.WriteString("  }\n")

	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority 0;\n")
	b.WriteString("    policy drop;\n")
	b.WriteString("  }\n")

	b.WriteString("}\n")

	if err := os.WriteFile(isolationFile, []byte(b.String()), 0600); err != nil {
		return err
	}

	// 3. Ensure main config includes our file
	conf, err := os.ReadFile(nftConf)
	if err != nil {
		return err
	}

	if !strings.Contains(string(conf), isolationFile) {
		conf = append(conf, []byte("\ninclude \""+isolationFile+"\"\n")...)
		if err := os.WriteFile(nftConf, conf, 0644); err != nil {
			return err
		}
	}

	// 4. Apply nftables rules
	if err := exec.Command("nft", "-f", nftConf).Run(); err != nil {
		return errors.New(fmt.Sprintf("failed to apply nft rules: %w", err))
	}

	return nil
}



func unisolateHostLinux() error {
	if os.Geteuid() != 0 {
		return errors.New(fmt.Sprintf("must run as root"))
	}

	backup, err := os.ReadFile(nftBackup)
	if err != nil {
		return err
	}

	if err := os.WriteFile(nftConf, backup, 0644); err != nil {
		return err
	}

	return exec.Command("nft", "-f", nftConf).Run()
}

func isolateHost(allowIPs []string) error {
	if runtime.GOOS == "darwin" {
		return isolateHostMacos(allowIPs)
	} else {
		return isolateHostLinux(allowIPs)
	}

	return errors.New(fmt.Sprintf("isolation not supported on this platform"))
}

func unisolateHost() error {
	if runtime.GOOS == "darwin" {
		return unisolateHostMacos()
	} else {
		return unisolateHostLinux()
	}

	return errors.New(fmt.Sprintf("un-isolation not supported on this platform"))
}

// fileExists checks if a file exists
func checkFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func Screenshot() ([]shuffle.ScreenshotWrapper, error) {
	if runtime.GOOS == "darwin" {
		return ScreenshotMacos()
	} else if runtime.GOOS == "linux" {
		allScreens, err := ScreenshotLinux()
		if err == nil && len(allScreens) > 0 {
			return allScreens, nil
		} else {
			return nil, errors.New(fmt.Sprintf("failed to capture screenshot on Linux: %w", err))
		}
	} else {
		return nil, errors.New(fmt.Sprintf(fmt.Sprintf("screenshot not supported on %s platform", runtime.GOOS)))
	}
}

// runCapture runs a capture command and reads back the output file.
func runCapture(path string, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, errors.New(fmt.Sprintf("%s: %w — %s", name, err, out))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%s produced no output at %s", name, path))
	}
	return data, nil
}

var ErrNoDisplay = fmt.Errorf("no display available: DISPLAY and WAYLAND_DISPLAY are both unset — running headless")
func ScreenshotLinux() ([]shuffle.ScreenshotWrapper, error) {
	switch {
	case os.Getenv("WAYLAND_DISPLAY") != "":
		return screenshotWayland()
	case os.Getenv("DISPLAY") != "":
		return screenshotX11()
	default:
		return nil, ErrNoDisplay
	}
}

// ── X11 ───────────────────────────────────────────────────────────────────────

// screenshotX11 captures each connected display by:
//  1. Parsing xrandr for per-display geometry (size + offset).
//  2. Capturing the full root window once with import or scrot.
//  3. Cropping each display's region from the root capture using convert.
//  4. Reading cursor position once with xdotool.
//
// This means one capture process regardless of display count, which is faster
// and avoids flickering artefacts from multiple sequential captures.
func screenshotX11() ([]shuffle.ScreenshotWrapper, error) {
	displays, err := displaySizeX11()
	if err != nil {
		return nil, err
	}

	// Capture the full root window — covers all monitors in one shot.
	rootPath := tempPathLinux()
	defer os.Remove(rootPath)
	if err := captureRootX11(rootPath); err != nil {
		return nil, err
	}

	// Cursor position is best-effort — zero if xdotool is not installed.
	cursor, _ := cursorPositionX11()

	wrappers := make([]shuffle.ScreenshotWrapper, 0, len(displays))
	for _, d := range displays {
		png, err := cropX11(rootPath, d)
		if err != nil {
			// Fall back to the full root image for this display rather than
			// failing the entire call.
			data, readErr := os.ReadFile(rootPath)
			if readErr != nil {
				return nil, fmt.Errorf("display %d: crop failed and root image unreadable: %w", d.DisplayID, err)
			}
			png = data
		}
		wrappers = append(wrappers, shuffle.ScreenshotWrapper{
			Image:      png,
			ScreenSize: d,
			Cursor:     cursor,
		})
	}
	return wrappers, nil
}

// captureRootX11 captures the full X11 root window into path.
// Tries import (ImageMagick) first, falls back to scrot.
func captureRootX11(path string) error {
	if err := runTool(path, "import", "-window", "root", path); err == nil {
		return nil
	}
	if err := runTool(path, "scrot", "--silent", path); err == nil {
		return nil
	}
	return fmt.Errorf(
		"X11 capture failed: neither 'import' (ImageMagick) nor 'scrot' is installed — " +
			"install one: apt install imagemagick  OR  apt install scrot",
	)
}

// cropX11 uses ImageMagick's convert to crop a display's region from the root image.
// Geometry string format: WxH+X+Y  (e.g. "1920x1080+1920+0" for the right monitor).
func cropX11(rootPath string, d shuffle.DisplaySize) ([]byte, error) {
	outPath := tempPathLinux()
	defer os.Remove(outPath)

	geometry := fmt.Sprintf("%dx%d+%d+%d", d.Width, d.Height, d.OffsetX, d.OffsetY)
	if err := runTool(outPath, "convert", rootPath, "-crop", geometry, "+repage", outPath); err != nil {
		return nil, fmt.Errorf("convert crop failed for display %d (%s): %w", d.DisplayID, geometry, err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("reading cropped image for display %d: %w", d.DisplayID, err)
	}
	return data, nil
}

// displaySizeX11 parses xrandr --current for all connected displays,
// returning size AND offset so we can crop the root image correctly.
func displaySizeX11() ([]shuffle.DisplaySize, error) {
	out, err := exec.Command("xrandr", "--current").Output()
	if err != nil {
		return nil, fmt.Errorf("xrandr failed: %w — install: apt install x11-xserver-utils", err)
	}

	var sizes []shuffle.DisplaySize
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	id := 1
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, " connected ") {
			continue
		}
		var w, h, x, y int
		for _, f := range strings.Fields(line) {
			// geometry token: 1920x1080+0+0
			if n, _ := fmt.Sscanf(f, "%dx%d+%d+%d", &w, &h, &x, &y); n == 4 {
				break
			}
		}
		if w == 0 || h == 0 {
			continue
		}
		sizes = append(sizes, shuffle.DisplaySize{
			DisplayID: id,
			Width:     w,
			Height:    h,
			OffsetX:   x,
			OffsetY:   y,
		})
		id++
	}
	if len(sizes) == 0 {
		return nil, fmt.Errorf("xrandr returned no connected displays")
	}
	return sizes, nil
}

// cursorPositionX11 reads the cursor position using xdotool.
// Returns a zero Position if xdotool is not installed — callers treat cursor
// as best-effort and should not fail on this.
// Install: apt install xdotool  OR  pacman -S xdotool
func cursorPositionX11() (shuffle.Position, error) {
	out, err := exec.Command("xdotool", "getmouselocation", "--shell").Output()
	if err != nil {
		return shuffle.Position{}, fmt.Errorf(
			"xdotool failed: %w — install: apt install xdotool  OR  pacman -S xdotool", err,
		)
	}

	// Output:
	//   X=123
	//   Y=456
	//   SCREEN=0
	//   WINDOW=12345678
	var pos shuffle.Position
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		var v float64
		if n, _ := fmt.Sscanf(line, "X=%f", &v); n == 1 {
			pos.X = v
		}
		if n, _ := fmt.Sscanf(line, "Y=%f", &v); n == 1 {
			pos.Y = v
		}
	}
	return pos, nil
}

// ── Wayland ───────────────────────────────────────────────────────────────────

// screenshotWayland tries wlroots-style capture first (grim -o per output),
// then falls back to GNOME-style (single combined image via grim without -o).
// Cursor is always zero — Wayland does not expose cursor position to clients.
func screenshotWayland() ([]shuffle.ScreenshotWrapper, error) {
	if wrappers, err := screenshotWlroots(); err == nil {
		return wrappers, nil
	}
	return screenshotGnomeWayland()
}

// screenshotWlroots captures each wlr output individually using grim -o.
// Requires: grim (apt install grim / pacman -S grim)
// Supported compositors: sway, river, Hyprland, and other wlroots-based ones.
func screenshotWlroots() ([]shuffle.ScreenshotWrapper, error) {
	displays, err := displaySizeWlrRandr()
	if err != nil {
		return nil, err
	}

	wrappers := make([]shuffle.ScreenshotWrapper, 0, len(displays))
	for _, d := range displays {
		path := tempPathLinux()
		if err := runTool(path, "grim", "-t", "png", "-o", d.OutputName, path); err != nil {
			os.Remove(path)
			return nil, fmt.Errorf(
				"grim failed for output %q: %w — install: apt install grim  OR  pacman -S grim", d.OutputName, err,
			)
		}
		data, err := os.ReadFile(path)
		os.Remove(path)
		if err != nil {
			return nil, fmt.Errorf("reading screenshot for output %q: %w", d.OutputName, err)
		}
		wrappers = append(wrappers, shuffle.ScreenshotWrapper{
			Image:      data,
			ScreenSize: d.DisplaySize,
			Cursor:     shuffle.Position{}, // not available on Wayland
		})
	}
	return wrappers, nil
}

// screenshotGnomeWayland captures all displays as one combined image using
// grim without the -o flag, then pairs it with sizes from gdbus.
// GNOME requires xdg-desktop-portal-gnome and may show a permission prompt.
func screenshotGnomeWayland() ([]shuffle.ScreenshotWrapper, error) {
	path := tempPathLinux()
	defer os.Remove(path)

	if err := runTool(path, "grim", "-t", "png", path); err != nil {
		return nil, fmt.Errorf(
			"Wayland capture failed: grim not found or compositor does not support "+
				"wlr-screencopy — install: apt install grim  OR  pacman -S grim. "+
				"Note: GNOME requires xdg-desktop-portal-gnome and may prompt for permission: %w", err,
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading Wayland screenshot: %w", err)
	}

	// Best-effort sizes — if gdbus fails we still return the image with zero size.
	sizes, err := displaySizeGnomeWayland()
	if err != nil || len(sizes) == 0 {
		sizes = []shuffle.DisplaySize{{DisplayID: 1}}
	}

	// We have one combined image but potentially multiple display size entries.
	// Return one wrapper per display with the same combined image — the caller
	// can use ScreenSize to understand the logical layout.
	wrappers := make([]shuffle.ScreenshotWrapper, len(sizes))
	for i, s := range sizes {
		wrappers[i] = shuffle.ScreenshotWrapper{
			Image:      data,
			ScreenSize: s,
			Cursor:     shuffle.Position{},
		}
	}
	return wrappers, nil
}

// wlrDisplay extends DisplaySize with the output name grim needs for -o.
type wlrDisplay struct {
	shuffle.DisplaySize
	OutputName string
}

// displaySizeWlrRandr parses wlr-randr output for output names and current
// resolution. OutputName is used by grim -o to target a specific output.
func displaySizeWlrRandr() ([]wlrDisplay, error) {
	out, err := exec.Command("wlr-randr").Output()
	if err != nil {
		return nil, fmt.Errorf("wlr-randr: %w", err)
	}

	// wlr-randr output format:
	//   HDMI-A-1 "Dell U2722D" (...)
	//     ...
	//     1920x1080 px, 60.000000 Hz (current)
	var displays []wlrDisplay
	var current wlrDisplay
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	id := 1
	for sc.Scan() {
		line := sc.Text()
		// Output header: first character is non-space (not indented).
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			// Save previous output if it had a valid current mode.
			if current.OutputName != "" && current.Width > 0 {
				current.DisplayID = id
				displays = append(displays, current)
				id++
			}
			current = wlrDisplay{OutputName: strings.Fields(line)[0]}
			continue
		}
		// Resolution line (indented, contains "current").
		trimmed := strings.TrimSpace(line)
		var w, h int
		if n, _ := fmt.Sscanf(trimmed, "%dx%d px", &w, &h); n == 2 && strings.Contains(trimmed, "current") {
			current.Width = w
			current.Height = h
		}
	}
	// Flush the last output.
	if current.OutputName != "" && current.Width > 0 {
		current.DisplayID = id
		displays = append(displays, current)
	}

	if len(displays) == 0 {
		return nil, fmt.Errorf("no current mode found in wlr-randr output")
	}
	return displays, nil
}

// displaySizeGnomeWayland queries display sizes from GNOME's Mutter via gdbus.
func displaySizeGnomeWayland() ([]shuffle.DisplaySize, error) {
	out, err := exec.Command("gdbus", "call", "--session",
		"--dest", "org.gnome.Mutter.DisplayConfig",
		"--object-path", "/org/gnome/Mutter/DisplayConfig",
		"--method", "org.gnome.Mutter.DisplayConfig.GetCurrentState",
	).Output()
	if err != nil {
		return nil, fmt.Errorf(
			"GNOME DisplayConfig gdbus query failed — "+
				"install wlr-randr as alternative: apt install wlr-randr: %w", err,
		)
	}

	// GVariant output — best-effort scan for WxH pairs that look like resolutions.
	var sizes []shuffle.DisplaySize
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	id := 1
	for sc.Scan() {
		var w, h int
		if n, _ := fmt.Sscanf(strings.TrimSpace(sc.Text()), "%d, %d,", &w, &h); n == 2 && w > 100 && h > 100 {
			sizes = append(sizes, shuffle.DisplaySize{DisplayID: id, Width: w, Height: h})
			id++
		}
	}
	if len(sizes) == 0 {
		return nil, fmt.Errorf("could not parse display sizes from GNOME DisplayConfig output")
	}
	return sizes, nil
}

// ── Standalone accessors ──────────────────────────────────────────────────────

// GetDisplaySizeLinux returns display sizes without capturing images.
// Prefer Screenshot() if you need both.
func GetDisplaySizeLinux() ([]shuffle.DisplaySize, error) {
	switch {
	case os.Getenv("WAYLAND_DISPLAY") != "":
		return displaySizeWayland()
	case os.Getenv("DISPLAY") != "":
		sizes, err := displaySizeX11()
		if err != nil {
			return nil, err
		}
		// Strip the DisplaySize from the extended X11 type.
		out := make([]shuffle.DisplaySize, len(sizes))
		for i, s := range sizes {
			out[i] = s
		}
		return out, nil
	default:
		return nil, ErrNoDisplay
	}
}

func displaySizeWayland() ([]shuffle.DisplaySize, error) {
	if displays, err := displaySizeWlrRandr(); err == nil {
		sizes := make([]shuffle.DisplaySize, len(displays))
		for i, d := range displays {
			sizes[i] = d.DisplaySize
		}
		return sizes, nil
	}
	return displaySizeGnomeWayland()
}

// GetCursorPositionLinux returns cursor position on X11.
// Always returns a zero Position on Wayland with an explanatory error.
func GetCursorPositionLinux() (shuffle.Position, error) {
	switch {
	case os.Getenv("WAYLAND_DISPLAY") != "":
		return shuffle.Position{}, fmt.Errorf(
			"cursor position unavailable on Wayland: the protocol does not expose " +
				"cursor coordinates by design — no workaround exists without a compositor-specific extension",
		)
	case os.Getenv("DISPLAY") != "":
		return cursorPositionX11()
	default:
		return shuffle.Position{}, ErrNoDisplay
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// runTool runs a command and returns an error if it exits non-zero.
// outPath is not written by this function — it is passed as an arg to the tool.
func runTool(outPath, name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w — %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func tempPathLinux() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("edr-%d.png", time.Now().UnixNano()))
}
