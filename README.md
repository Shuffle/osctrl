# osCTRL

`osCTRL` is a cross-platform Go library and agent toolkit for endpoint monitoring, compliance auditing, host containment, and remote-control automation. It provides APIs to interact with OS primitives, inspect system security posture, capture multi-monitor screens, simulate user input, isolate network traffic, and scan software and code inventories.

---

## 1. Inventory & Compliance Support Matrix

The table below outlines inventory discovery, security posture checks, and repository scanning across **Windows**, **macOS**, and **Linux**:

| Feature | Windows | macOS (Darwin) | Linux (X11 / Wayland) | Details & Implementation |
| :--- | :---: | :---: | :---: | :--- |
| **Installed Software** | ✅ Full | ✅ Full | ✅ Full | **Win**: 32/64-bit Registry Uninstall keys (`HKLM`/`HKCU`)<br>**Mac**: `/Applications`, `~/Applications`, & Homebrew<br>**Linux**: `dpkg`, `rpm`, `pacman`, `apk`, `snap`, `flatpak` |
| **Running Processes** | ✅ Full | ✅ Full | ✅ Full | Process enumeration (PID, binary path, command line arguments) |
| **Hard Drive Encryption** | ✅ Full | ✅ Full | ✅ Full | **Win**: BitLocker (`manage-bde`)<br>**Mac**: FileVault (`fdesetup status`)<br>**Linux**: LUKS (`lsblk` / `dmsetup`) |
| **Screen Auto-Lock** | ✅ Full | ✅ Full | ⚠️ Desktop Specific | **Win**: Lock screen idle timeout<br>**Mac**: `sysadminctl` / `defaults`<br>**Linux**: GNOME `gsettings` / X11 screensaver |
| **Automatic Updates** | ✅ Full | ✅ Full | ✅ Full | **Win**: Windows Update Service (`wuauserv`)<br>**Mac**: `softwareupdate --schedule`<br>**Linux**: `unattended-upgrades` / package timers |
| **Code Repository Scanner** | ✅ Full | ✅ Full | ✅ Full | Multi-threaded AST/manifest parser for Go, Python, JavaScript/TypeScript, Java, Ruby, and .NET |

---

## 2. Host Isolation & Terminal Support Matrix

The table below outlines incident response containment, process termination, and command execution across **Windows**, **macOS**, and **Linux**:

| Feature | Windows | macOS (Darwin) | Linux (X11 / Wayland) | Details & Implementation |
| :--- | :---: | :---: | :---: | :--- |
| **Network Isolation** | ✅ Full | ✅ Full | ✅ Full | **Win**: `netsh advfirewall` firewall rules<br>**Mac**: `pfctl` packet filter anchors<br>**Linux**: `nftables` atomic table swap (`/etc/nftables.conf`) |
| **IP Whitelisting** | ✅ Full | ✅ Full | ✅ Full | Preserves access to control plane / approved IP addresses during host containment |
| **Command Execution** | ✅ Full | ✅ Full | ✅ Full | Shell execution via `cmd.exe`/`powershell` (Windows), `/bin/zsh` (macOS), and `/bin/bash` (Linux) |
| **Process Termination** | ✅ Full | ✅ Full | ✅ Full | Force-kill processes by PID (`taskkill` / Win32 `TerminateProcess` / `SIGKILL`) |

---

## 3. Remote Control & Screen Capture Support Matrix

The table below outlines screen capture, accessibility introspection, and input simulation across **Windows**, **macOS**, and **Linux**:

| Feature | Windows | macOS (Darwin) | Linux (X11) | Linux (Wayland) | Details & Implementation |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Multi-Display Capture** | ✅ Full | ✅ Full | ✅ Full | ✅ Full | **Win**: `System.Drawing`<br>**Mac**: CoreGraphics<br>**Linux**: `import`/`scrot` + `convert` (X11) / `grim` (Wayland) |
| **Cursor Position** | ✅ Full | ✅ Full | ✅ Full | ❌ Not Supported | Global cursor coordinates are unavailable on Wayland by protocol design |
| **UI Element Tree** | ⚠️ Window Bounds | ✅ Deep Tree | ⚠️ Window Bounds | ⚠️ Window Bounds | **Win**: Win32 `GetForegroundWindow` / `GetWindowRect`<br>**Mac**: `AXUIElement` recursive accessibility tree<br>**Linux**: `xdotool` + `xwininfo` + `xprop` |
| **Mouse Move & Click** | ✅ Full | ✅ Full | ✅ Full | ❌ Limited | **Win**: `user32.dll` (`SetCursorPos`, `mouse_event`)<br>**Mac**: CoreGraphics CGO<br>**Linux**: `xdotool` |
| **Mouse Drag** | ✅ Full | ✅ Full | ✅ Full | ❌ Limited | Drag simulation with Left / Right / Middle buttons |
| **Keyboard Typing** | ✅ Full | ✅ Full | ✅ Full | ❌ Limited | **Win**: `KEYEVENTF_UNICODE`<br>**Mac**: Native CoreGraphics events<br>**Linux**: `xdotool type` |
| **Keyboard Hotkeys** | ✅ Full | ✅ Full | ✅ Full | ❌ Limited | Modifier key combos (Ctrl, Shift, Alt, Win/Cmd) with reverse keyup release |
| **System Wait** | ✅ Full | ✅ Full | ✅ Full | ✅ Full | Execution delays between action batches |

---

## Detailed Technical Breakdown

### 1. Compliance, Inventory & Sensors
- **Software Inventory**:
  - **Windows**: Queries 32-bit and 64-bit Registry paths (`HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` and `HKCU`).
  - **macOS**: Parses system applications (`/Applications`, `~/Applications`) and active Homebrew installations.
  - **Linux**: Queries native package managers (`dpkg`, `rpm`, `pacman`, `apk`), snaps, and flatpaks.
- **Security Sensors**:
  - **Disk Encryption**: Checks BitLocker status on Windows via `manage-bde`, FileVault status on macOS via `fdesetup status`, and LUKS block devices on Linux via `lsblk`/`dmsetup`.
  - **Screen Lock Timeout**: Detects screen saver and power idle lock thresholds.
  - **Auto Updates**: Verifies that scheduled automated OS updates are active.
- **Universal Code Scanner**:
  - Multi-threaded scanner identifying project types and extracting package manifests: Go (`go.mod`), Python (`pyproject.toml`, `requirements.txt`, `Pipfile`), JS/TS (`package.json`), Java (`pom.xml`, `build.gradle`), Ruby (`Gemfile`), and .NET (`.csproj`, `.fsproj`, `.vbproj`).
  - Platform-aware exclusion lists automatically ignore OS noise (`AppData`, `Program Files`, `$Recycle.Bin` on Windows, `/System`, `/Library` on macOS) and build caches (`node_modules`, `vendor`, `.venv`, Go module cache).

### 2. Host Isolation & Incident Response
- **Windows**: Adds block rules via `netsh advfirewall` for all inbound/outbound network traffic while creating high-priority exceptions for whitelisted IPs.
- **macOS**: Loads `pfctl` rules blocking network traffic outside of whitelisted IP destinations.
- **Linux**: Backs up `/etc/nftables.conf` and atomically swaps the active table with an isolation ruleset allowing only loopback and whitelisted IPs. Restores previous configuration on un-isolate.

### 3. Screen Capture & UI State Inspection
- **Screenshots**:
  - **Windows**: Captured per screen using `System.Drawing.Graphics.CopyFromScreen` via non-interactive PowerShell.
  - **macOS**: Captured per display via `CGDisplayCreateImage` with native cursor overlay.
  - **Linux (X11)**: Captured via `import` or `scrot`, cropped per display via `convert` using `xrandr` geometry.
  - **Linux (Wayland)**: Captured per-output via `grim -o` with `wlr-randr`, or single combined capture via GNOME portal.
- **UI Element Tree (`FetchFocusedElement`)**:
  - **Windows**: Inspects foreground window via `user32.dll` (`GetForegroundWindow`, `GetWindowRect`, `GetWindowTextW`) and resolves executable name via `QueryFullProcessImageName`.
  - **macOS**: Full deep UI hierarchy traversal via `AXUIElementCopyAttributeValue` resolving nested interactive controls, roles, labels, and bounding boxes.
  - **Linux**: Inspects active window via `xdotool getactivewindow`, `xwininfo`, and `xprop` (`WM_CLASS`), providing window title, dimensions, center click point, and application name.

### 4. Remote Control Action Reference

Supported actions in `RemoteControlActionBatch`:

| Action | Parameters | Description |
| :--- | :--- | :--- |
| `mouse.move` | `x` (int), `y` (int) | Moves cursor to target screen coordinates |
| `mouse.click` | `x` (int), `y` (int), `button` ("left" / "right" / "middle"), `delay_ms` (int) | Positions cursor, pauses, and clicks specified button |
| `mouse.drag` | `from_x`, `from_y`, `to_x`, `to_y`, `button` | Performs mouse drag from origin to destination coordinates |
| `keyboard.press` | `key` (int / string), `key_name` (string) | Presses and releases an individual key code or key name |
| `keyboard.type` | `text` (string) | Types arbitrary text with Unicode support |
| `keyboard.hotkey` | `keys` (list / comma-string) | Presses modifier keys in sequence and releases in reverse order (e.g. `["ctrl", "c"]`, `["cmd", "space"]`) |
| `system.wait` | `ms` (int) | Pauses execution for the specified duration |

---

## Cross-Platform Compilation

`osctrl` is designed for clean cross-compilation with zero CGO dependencies required for Linux and Windows targets:

```bash
# Windows (amd64)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...

# macOS (arm64 / amd64)
GOOS=darwin go build ./...

# Linux (amd64)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...
```


