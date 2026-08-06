//go:build darwin

package osctrl 

/*
#cgo LDFLAGS: -framework ApplicationServices

#import <ApplicationServices/ApplicationServices.h>

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
		key := getInt(a.Params, "key")
		keyPress(uint16(key))

	// -------- Utility --------

	case "system.wait":
		ms := getInt(a.Params, "ms")
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
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

func keyPress(vk uint16) {
	// macOS uses CGKeyCode (virtual keycodes)
	C.NativeKeyEvent(C.CGKeyCode(vk), true)
	time.Sleep(30 * time.Millisecond)
	C.NativeKeyEvent(C.CGKeyCode(vk), false)
}

