//go:build !darwin

package webview

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

type nonDarwinWindow struct {
	cfg        WindowConfig
	listener   net.Listener
	server     *http.Server
	port       int
	cmd        *exec.Cmd
	clients    map[chan string]bool
	clientsMu  sync.Mutex
	isCreated  bool
	isVisible  bool
	mu         sync.Mutex
}

// New creates a new Window instance on non-darwin platforms (Windows / Linux).
// The webview server and application window are lazily initialized when Show() is called.
func New(cfg WindowConfig) Window {
	return &nonDarwinWindow{
		cfg:     cfg,
		clients: make(map[chan string]bool),
	}
}

func (w *nonDarwinWindow) Show() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.isCreated {
		if err := w.startLocalServer(); err != nil {
			log.Printf("[ERROR] Failed to start local webview server: %v", err)
			return
		}
		w.isCreated = true
	}

	w.isVisible = true
	w.launchAppWindow()
}

func (w *nonDarwinWindow) startLocalServer() error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	w.listener = listener
	w.port = listener.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()

	// Serve the embedded HTML with injected bridge polyfill
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		bridgeScript := fmt.Sprintf(`
<script>
window.bridgeCall = async function(action, payload) {
    try {
        const res = await fetch('/api/bridge', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: action, payload: payload})
        });
        return await res.text();
    } catch (e) {
        console.error('bridge error', e);
        return JSON.stringify({error: e.message});
    }
};
window.startWindowDrag = function() {};
window.setTitlebarNoDragWidth = function() {};
window.setModalActive = function() {};
window.getInitialState = function() { return window.bridgeCall('getInitialState', ''); };
window.listProjects = function() { return window.bridgeCall('listProjects', ''); };
window.selectProject = function(path) { return window.bridgeCall('selectProject', path); };
window.setPermissionPolicy = function(policy) { return window.bridgeCall('setPermissionPolicy', policy); };
window.runPrompt = function(prompt, bypass, convId) { return window.bridgeCall('runPrompt', JSON.stringify({prompt: prompt, bypass: bypass, conversation_id: convId || ''})); };
window.respondApproval = function(id, approved) { return window.bridgeCall('respondApproval', JSON.stringify({id: id, approved: approved})); };
window.respondApprovalWithOptions = function(id, option, commandPrefix, scope, scopeId) { return window.bridgeCall('respondApprovalWithOptions', JSON.stringify({id: id, option: option, commandPrefix: commandPrefix, scope: scope, scopeId: scopeId})); };
window.getApprovalRules = function() { return window.bridgeCall('getApprovalRules', ''); };
window.addApprovalRule = function(rule) { return window.bridgeCall('addApprovalRule', typeof rule === 'string' ? rule : JSON.stringify(rule)); };
window.revokeApprovalRule = function(id) { return window.bridgeCall('revokeApprovalRule', id); };
window.clearApprovalRules = function() { return window.bridgeCall('clearApprovalRules', ''); };
window.setPinnedConversations = function(pinned) { return window.bridgeCall('setPinnedConversations', typeof pinned === 'string' ? pinned : JSON.stringify(pinned)); };
window.takeScreenshot = function() { return window.bridgeCall('takeScreenshot', ''); };
window.inspectUI = function() { return window.bridgeCall('inspectUI', ''); };
window.requestOSPermission = function(perm) { return window.bridgeCall('requestOSPermission', perm); };
window.updateAuth = function(authData) { return window.bridgeCall('updateAuth', typeof authData === 'string' ? authData : JSON.stringify(authData)); };
window.setAiConfig = function(url, key, policy, model) { return window.bridgeCall('setAiConfig', JSON.stringify({url: url, key: key, permission_policy: policy || '', model: model || ''})); };
window.startOAuthLogin = function(url) { return window.bridgeCall('startOAuthLogin', url || ''); };
window.setOAuthToken = function(token, org, env) { return window.bridgeCall('setOAuthToken', JSON.stringify({token: token, org: org, env: env})); };
window.windowAction = function(act) { return window.bridgeCall('windowAction', act); };
window.chooseDirectory = function() { return window.bridgeCall('chooseDirectory', ''); };
window.chooseFile = function() { return window.bridgeCall('chooseFile', ''); };
window.clearHistory = function() { return window.bridgeCall('clearHistory', ''); };
window.saveAllSettings = function(settings) { return window.bridgeCall('saveAllSettings', typeof settings === 'string' ? settings : JSON.stringify(settings)); };
window.setProjectPermissions = function(project, perms) { return window.bridgeCall('setProjectPermissions', JSON.stringify({project: project, permissions: perms})); };

// SSE channel for push events from EvaluateJS
const evtSource = new EventSource('/api/events');
evtSource.onmessage = function(e) {
    try {
        eval(e.data);
    } catch(err) {
        console.error('eval error', err);
    }
};
</script>
`)

		html := w.cfg.HTML
		if strings.Contains(html, "<head>") {
			html = strings.Replace(html, "<head>", "<head>"+bridgeScript, 1)
		} else {
			html = bridgeScript + html
		}
		io.WriteString(rw, html)
	})

	// Bridge API endpoint
	mux.HandleFunc("/api/bridge", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Action  string `json:"action"`
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		resp := ""
		if w.cfg.BridgeHandler != nil {
			resp = w.cfg.BridgeHandler(req.Action, req.Payload)
		}
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(rw, resp)
	})

	// SSE endpoint for server-to-client evaluations
	mux.HandleFunc("/api/events", func(rw http.ResponseWriter, r *http.Request) {
		flusher, ok := rw.(http.Flusher)
		if !ok {
			http.Error(rw, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		rw.Header().Set("Content-Type", "text/event-stream")
		rw.Header().Set("Cache-Control", "no-cache")
		rw.Header().Set("Connection", "keep-alive")

		msgChan := make(chan string, 16)
		w.clientsMu.Lock()
		w.clients[msgChan] = true
		w.clientsMu.Unlock()

		defer func() {
			w.clientsMu.Lock()
			delete(w.clients, msgChan)
			close(msgChan)
			w.clientsMu.Unlock()
		}()

		notify := r.Context().Done()
		for {
			select {
			case <-notify:
				return
			case msg, ok := <-msgChan:
				if !ok {
					return
				}
				fmt.Fprintf(rw, "data: %s\n\n", msg)
				flusher.Flush()
			}
		}
	})

	server := &http.Server{Handler: mux}
	w.server = server

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[ERROR] Webview HTTP server stopped: %v", err)
		}
	}()

	return nil
}

func (w *nonDarwinWindow) launchAppWindow() {
	url := fmt.Sprintf("http://127.0.0.1:%d", w.port)
	appArg := fmt.Sprintf("--app=%s", url)
	width := w.cfg.Width
	if width <= 0 {
		width = 950
	}
	height := w.cfg.Height
	if height <= 0 {
		height = 700
	}
	sizeArg := fmt.Sprintf("--window-size=%d,%d", width, height)

	go func() {
		if runtime.GOOS == "windows" {
			// Try Edge app mode first, then Chrome, then default browser
			edgeCandidates := []string{
				`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
				`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
				"msedge.exe",
			}
			for _, bin := range edgeCandidates {
				cmd := exec.Command(bin, appArg, sizeArg)
				if err := cmd.Start(); err == nil {
					w.cmd = cmd
					return
				}
			}
			chromeCandidates := []string{
				`C:\Program Files\Google\Chrome\Application\chrome.exe`,
				`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
				"chrome.exe",
			}
			for _, bin := range chromeCandidates {
				cmd := exec.Command(bin, appArg, sizeArg)
				if err := cmd.Start(); err == nil {
					w.cmd = cmd
					return
				}
			}
			// Fallback: default browser
			_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
		} else {
			// Linux: try Chrome / Chromium in app mode, then xdg-open
			browsers := []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser"}
			for _, bin := range browsers {
				if _, err := exec.LookPath(bin); err == nil {
					cmd := exec.Command(bin, appArg, sizeArg)
					if err := cmd.Start(); err == nil {
						w.cmd = cmd
						return
					}
				}
			}
			// Fallback: xdg-open
			_ = exec.Command("xdg-open", url).Start()
		}
	}()
}

func (w *nonDarwinWindow) Hide() {
	w.isVisible = false
}

func (w *nonDarwinWindow) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.isVisible = false
	if w.server != nil {
		_ = w.server.Close()
		w.server = nil
	}
	if w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
		w.cmd = nil
	}
	w.isCreated = false
}

func (w *nonDarwinWindow) Minimize() {}

func (w *nonDarwinWindow) Maximize() {}

func (w *nonDarwinWindow) EvaluateJS(js string) {
	if js == "" {
		return
	}
	w.clientsMu.Lock()
	defer w.clientsMu.Unlock()

	for ch := range w.clients {
		select {
		case ch <- js:
		default:
		}
	}
}

func (w *nonDarwinWindow) IsVisible() bool {
	return w.isVisible
}

func (w *nonDarwinWindow) IsCreated() bool {
	return w.isCreated
}

// ChooseFolder presents a directory chooser dialog on Windows and Linux.
func ChooseFolder(title, prompt string) (string, error) {
	if runtime.GOOS == "windows" {
		psScript := `Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.FolderBrowserDialog; $f.Description = '` + title + `'; if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.SelectedPath }`
		out, err := exec.Command("powershell", "-NoProfile", "-Command", psScript).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		return "", err
	}

	// Linux: try zenity then kdialog
	if _, err := exec.LookPath("zenity"); err == nil {
		out, err := exec.Command("zenity", "--file-selection", "--directory", "--title="+title).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	if _, err := exec.LookPath("kdialog"); err == nil {
		out, err := exec.Command("kdialog", "--getexistingdirectory", "--title", title).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	return "", fmt.Errorf("no dialog utility (zenity or kdialog) found")
}

// ChooseFile presents a file chooser dialog on Windows and Linux.
func ChooseFile(title, prompt string) (string, error) {
	if runtime.GOOS == "windows" {
		psScript := `Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.OpenFileDialog; $f.Title = '` + title + `'; if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $f.FileName }`
		out, err := exec.Command("powershell", "-NoProfile", "-Command", psScript).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		return "", err
	}

	// Linux: try zenity then kdialog
	if _, err := exec.LookPath("zenity"); err == nil {
		out, err := exec.Command("zenity", "--file-selection", "--title="+title).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	if _, err := exec.LookPath("kdialog"); err == nil {
		out, err := exec.Command("kdialog", "--getopenfilename", "--title", title).Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
	}
	return "", fmt.Errorf("no dialog utility (zenity or kdialog) found")
}
