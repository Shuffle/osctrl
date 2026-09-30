package webview

// WindowConfig configures a native desktop window with embedded web view.
type WindowConfig struct {
	Title         string
	Width         int
	Height        int
	HTML          string
	IconPNG       []byte
	ProcessName   string
	BridgeHandler func(action string, payload string) string
}

// Window defines the cross-platform lifecycle interface for the native webview window.
type Window interface {
	// Show makes the window visible, bringing it to the front.
	// If the window has not been created yet, it will be instantiated lazily.
	Show()

	// Hide hides the window without destroying its underlying webview state.
	Hide()

	// Close closes and tears down the window.
	Close()

	// Minimize minimizes the window.
	Minimize()

	// Maximize zooms or toggles full screen for the window.
	Maximize()

	// EvaluateJS executes a JavaScript snippet inside the webview.
	EvaluateJS(js string)

	// IsVisible returns true if the window is currently visible.
	IsVisible() bool

	// IsCreated returns true if the native window and webview have been initialized.
	IsCreated() bool

	// Prewarm instantiates and pre-renders the window and webview in background.
	Prewarm()
}
