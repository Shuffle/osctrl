//go:build darwin

package webview

/*
#cgo CFLAGS: -x objective-c -Wno-deprecated-literal-operator
#cgo LDFLAGS: -framework ApplicationServices -framework CoreGraphics -framework CoreFoundation -framework Cocoa -framework WebKit

#include "darwin.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"log"
	"sync"
	"unsafe"
)

var (
	activeWindowMu sync.RWMutex
	activeWindow   *darwinWindow
)

type darwinWindow struct {
	cfg WindowConfig
	mu  sync.Mutex
}

//export HandleBridgeAction
func HandleBridgeAction(cAction *C.char, cPayload *C.char) (cRes *C.char) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ERROR] Recovered from panic in HandleBridgeAction: %v", r)
			cRes = C.CString(fmt.Sprintf(`{"status":"error","error":%q,"error_type":"execution_error","fix_help":"Backend recovered from an internal panic: %v"}`, fmt.Sprintf("Internal bridge error: %v", r), r))
		}
	}()

	if cAction == nil {
		return C.CString(`{"error": "nil action"}`)
	}
	action := C.GoString(cAction)
	payload := ""
	if cPayload != nil {
		payload = C.GoString(cPayload)
	}

	activeWindowMu.RLock()
	win := activeWindow
	activeWindowMu.RUnlock()

	if win == nil || win.cfg.BridgeHandler == nil {
		return C.CString(`{"error": "bridge handler not initialized"}`)
	}

	resp := win.cfg.BridgeHandler(action, payload)
	return C.CString(resp)
}

// New creates a new Window instance.
// Note: It does NOT instantiate the WKWebView or NSWindow on creation.
// Window and webview are lazily instantiated when Show() is called.
func New(cfg WindowConfig) Window {
	win := &darwinWindow{
		cfg: cfg,
	}

	activeWindowMu.Lock()
	activeWindow = win
	activeWindowMu.Unlock()

	// Configure app identity if process name or icon is provided
	if len(cfg.IconPNG) > 0 || cfg.ProcessName != "" {
		name := cfg.ProcessName
		if name == "" {
			name = cfg.Title
		}
		cName := C.CString(name)
		defer C.free(unsafe.Pointer(cName))

		if len(cfg.IconPNG) > 0 {
			cIcon := C.CBytes(cfg.IconPNG)
			defer C.free(cIcon)
			C.ApplyAppIdentity(cName, cIcon, C.int(len(cfg.IconPNG)))
		} else {
			C.ApplyAppIdentity(cName, nil, 0)
		}
	}

	return win
}

func (w *darwinWindow) Show() {
	w.mu.Lock()
	defer w.mu.Unlock()

	activeWindowMu.Lock()
	activeWindow = w
	activeWindowMu.Unlock()

	cTitle := C.CString(w.cfg.Title)
	defer C.free(unsafe.Pointer(cTitle))

	cHtml := C.CString(w.cfg.HTML)
	// cHtml is freed in C ShowAgentWindow
	C.ShowAgentWindow(cTitle, C.int(w.cfg.Width), C.int(w.cfg.Height), cHtml)
}

func (w *darwinWindow) Prewarm() {
	w.mu.Lock()
	defer w.mu.Unlock()

	activeWindowMu.Lock()
	activeWindow = w
	activeWindowMu.Unlock()

	cTitle := C.CString(w.cfg.Title)
	defer C.free(unsafe.Pointer(cTitle))

	cHtml := C.CString(w.cfg.HTML)
	// cHtml is freed in C PrewarmAgentWindow
	C.PrewarmAgentWindow(cTitle, C.int(w.cfg.Width), C.int(w.cfg.Height), cHtml)
}

func (w *darwinWindow) Hide() {
	C.HideAgentWindow()
}

func (w *darwinWindow) Close() {
	cAct := C.CString("close")
	defer C.free(unsafe.Pointer(cAct))
	C.WindowAction(cAct)
}

func (w *darwinWindow) Minimize() {
	cAct := C.CString("minimize")
	defer C.free(unsafe.Pointer(cAct))
	C.WindowAction(cAct)
}

func (w *darwinWindow) Maximize() {
	cAct := C.CString("maximize")
	defer C.free(unsafe.Pointer(cAct))
	C.WindowAction(cAct)
}

func (w *darwinWindow) EvaluateJS(js string) {
	if js == "" {
		return
	}
	cJs := C.CString(js)
	defer C.free(unsafe.Pointer(cJs))
	C.EvaluateJSInAgentWindow(cJs)
}

func (w *darwinWindow) IsVisible() bool {
	return C.IsAgentWindowVisible() != 0
}

func (w *darwinWindow) IsCreated() bool {
	return C.IsAgentWindowCreated() != 0
}

// ChooseFolder presents a macOS directory chooser dialog.
func ChooseFolder(title, prompt string) (string, error) {
	cTitle := C.CString(title)
	defer C.free(unsafe.Pointer(cTitle))
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))

	cPath := C.ChooseFolderDialog(cTitle, cPrompt)
	if cPath == nil {
		return "", nil
	}
	path := C.GoString(cPath)
	C.free(unsafe.Pointer(cPath))
	return path, nil
}

// ChooseFile presents a macOS file chooser dialog.
func ChooseFile(title, prompt string) (string, error) {
	cTitle := C.CString(title)
	defer C.free(unsafe.Pointer(cTitle))
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))

	cPath := C.ChooseFileDialog(cTitle, cPrompt)
	if cPath == nil {
		return "", nil
	}
	path := C.GoString(cPath)
	C.free(unsafe.Pointer(cPath))
	return path, nil
}
