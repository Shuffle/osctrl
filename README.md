# osCTRL

`osCTRL` is a cross-platform Go library and agent toolkit for endpoint monitoring, security auditing, and remote-controlling operating systems. It provides APIs to interact with OS primitives, inspect UI states, capture multi-monitor screens, simulate user input, isolate network traffic, and scan system and software inventory.

---

## OS Feature Support Matrix

The table below outlines core capabilities supported across **Windows**, **macOS**, and **Linux**:

| Feature Area | Sub-Feature | Windows | macOS (Darwin) | Linux (X11) | Linux (Wayland) | Notes & Implementation |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Screenshots** | Multi-Display Capture | ✅ Full | ✅ Full | ✅ Full | ✅ Full | **Win**: `System.Drawing`<br>**Mac**: CoreGraphics<br>**Linux**: `import`/`scrot` (X11) / `grim` (Wayland) |
| | Cursor Position | ✅ Full | ✅ Full | ✅ Full | ❌ Not Supported | Global cursor coordinates are unavailable on Wayland by protocol design |
| | UI Element Tree | ⚠️ Window Bounds | ✅ Deep Tree | ⚠️ Window Bounds | ⚠️ Window Bounds | **Win**: Win32 `GetForegroundWindow`<br>**Mac**: `AXUIElement` recursive tree<br>**Linux**: `xdotool` / `xwininfo` / `xprop` |
| **Remote Control** | Mouse Move / Click | ✅ Full | ✅ Full | ✅ Full | ❌ Limited | **Win**: `user32.dll` (`SetCursorPos`, `mouse_event`)<br>**Mac**: CoreGraphics CGO<br>**Linux**: `xdotool` |
| | Mouse Drag | ✅ Full | ✅ Full | ✅ Full | ❌ Limited | Drag simulation with Left / Right / Middle buttons |
| | Keyboard Typing | ✅ Full | ✅ Full | ✅ Full | ❌ Limited | **Win**: `KEYEVENTF_UNICODE`<br>**Mac**: Native CG events<br>**Linux**: `xdotool type` |
| | Keyboard Hotkeys | ✅ Full | ✅ Full | ✅ Full | ❌ Limited | Key combinations with modifier sequences (Ctrl, Shift, Alt, Win/Cmd) & reverse keyup |
| | System Wait | ✅ Full | ✅ Full | ✅ Full | ✅ Full | Delays and pauses between action executions |
| **Host Isolation** | Network Containment | ✅ Full | ✅ Full | ✅ Full | ✅ Full | **Win**: `netsh advfirewall`<br>**Mac**: `pfctl`<br>**Linux**: `nftables` |
| | IP Whitelisting | ✅ Full | ✅ Full | ✅ Full | ✅ Full | Maintains connectivity to control plane and approved IP addresses |
| **Software Inventory** | Installed Packages | ✅ Full | ✅ Full | ✅ Full | ✅ Full | **Win**: Registry Uninstall keys (`HKLM`/`HKCU`)<br>**Mac**: `/Applications` & Homebrew<br>**Linux**: `dpkg`/`rpm`/`pacman`/`snap`/`flatpak` |
| | Running Processes | ✅ Full | ✅ Full | ✅ Full | ✅ Full | Process enumeration and termination |
| **Security Sensors** | Hard Drive Encryption | ✅ Full | ✅ Full | ✅ Full | ✅ Full | **Win**: BitLocker (`manage-bde`)<br>**Mac**: FileVault (`fdesetup`)<br>**Linux**: LUKS / `lsblk` |
| | Auto-Lock Timeout | ✅ Full | ✅ Full | ✅ Full | ⚠️ Desktop Specific | **Win**: Screen lock query<br>**Mac**: `sysadminctl` / `defaults`<br>**Linux**: GNOME `gsettings` / X11 screensaver |
| | Auto-Update Checks | ✅ Full | ✅ Full | ✅ Full | ✅ Full | **Win**: Windows Update Service (`wuauserv`)<br>**Mac**: `softwareupdate`<br>**Linux**: `unattended-upgrades` |
| **Code Scanner** | Repository Discovery | ✅ Full | ✅ Full | ✅ Full | ✅ Full | Multi-threaded scanner for Go, Python, JS/TS, Java, Ruby, and .NET |

---

## Detailed OS Breakdown

### 1. Windows Capabilities
- **Screenshots & UI State**:
  - Captures each display individually using `System.Drawing.Graphics.CopyFromScreen` via hidden non-interactive PowerShell execution.
  - Queries active cursor position via `[System.Windows.Forms.Cursor]::Position`.
  - Introspects the focused foreground window via native Win32 APIs (`user32.dll` `GetForegroundWindow`, `GetWindowRect`, `GetWindowTextW`, `GetWindowThreadProcessId`) and process lookup (`QueryFullProcessImageName`), returning window dimensions, click point center, title, and executable name.
- **Remote Control Simulation**:
  - `mouse.move`: Cursor placement via Win32 `SetCursorPos`.
  - `mouse.click` / `mouse.drag`: Click and drag simulation via `mouse_event` (`MOUSE_LEFTDOWN`, `MOUSE_LEFTUP`, `MOUSE_RIGHTDOWN`, `MOUSE_RIGHTUP`).
  - `keyboard.type`: Unicode character typing via `keybd_event` and `KEYEVENTF_UNICODE`.
  - `keyboard.hotkey` / `keyboard.press`: Key combos and hotkeys using virtual key code mapping (`keyNameToVK`).
- **Security & System Sensors**:
  - Network isolation using `netsh advfirewall firewall` rules with IP whitelist support.
  - BitLocker encryption checks via `manage-bde`.
  - Installed software scanning via 32-bit and 64-bit Registry Uninstall keys (`HKLM` and `HKCU`).

### 2. macOS Capabilities
- **Screenshots & UI State**:
  - Multi-monitor capture via `CGDisplayCreateImage` with native cursor position overlay.
  - Full deep UI hierarchy traversal via macOS Accessibility APIs (`AXUIElementCopyAttributeValue`), resolving nested interactive elements, roles, labels, and bounding boxes.
- **Remote Control Simulation**:
  - Native CoreGraphics CGO bindings for mouse movements, clicks, drags, key presses, Unicode text typing (`NativeTypeText`), and modifier hotkeys.
- **Security & System Sensors**:
  - Network isolation via `pfctl` anchor rules with IP whitelisting.
  - FileVault encryption detection via `fdesetup status`.
  - Application inventory scanning from `/Applications`, `~/Applications`, and Homebrew.

### 3. Linux Capabilities
- **Screenshots & UI State**:
  - **X11**: Multi-monitor capture with `import` or `scrot`, cropped per display via `convert` based on `xrandr` geometry. Cursor queried via `xdotool getmouselocation`. Active window bounds, application name (`WM_CLASS`), and title queried via `xdotool getactivewindow`, `xwininfo`, and `xprop`.
  - **Wayland**: Per-output capture via `grim -o` with `wlr-randr`, or combined desktop capture via GNOME portal.
- **Remote Control Simulation**:
  - Full input simulation on X11 using `xdotool` (`mousemove`, `click`, `mousedown`, `mouseup`, `type`, `key`). Limited on Wayland due to protocol security boundaries.
- **Security & System Sensors**:
  - Network isolation using `nftables` (`/etc/nftables.conf`) backup and restore with IP whitelisting.
  - LUKS disk encryption status via `lsblk` and `dmsetup`.
  - Package discovery across `dpkg`, `rpm`, `pacman`, `apk`, `snap`, and `flatpak`.

---

## Universal Code Scanner

A multi-threaded project scanner discovering code repositories and dependency manifests across all platforms:
- **Languages**: Go (`go.mod`), Python (`pyproject.toml`, `requirements.txt`, `Pipfile`), JavaScript/TypeScript (`package.json`), Java (`pom.xml`, `build.gradle`), Ruby (`Gemfile`, `Rakefile`), and .NET (`.csproj`, `.fsproj`, `.vbproj`).
- **Platform-Aware Exclusions**: Automatically excludes system folders (`AppData`, `Program Files`, `$Recycle.Bin` on Windows, `/System`, `/Library` on macOS), VCS metadata (`.git`), build outputs (`dist`, `build`, `target`, `bin`, `obj`), and package caches (`node_modules`, `vendor`, `.venv`, Go module cache).

---

## Cross-Platform Compilation

`osctrl` builds cleanly without CGO dependencies for Linux and Windows targets:

```bash
# Windows (amd64)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...

# macOS (arm64 / amd64)
GOOS=darwin go build ./...

# Linux (amd64)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...
```

