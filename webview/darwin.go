//go:build darwin

package webview

/*
#cgo CFLAGS: -x objective-c -Wno-deprecated-literal-operator
#cgo LDFLAGS: -framework ApplicationServices -framework CoreGraphics -framework CoreFoundation -framework Cocoa -framework WebKit

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>

extern char* HandleBridgeAction(char* action, char* payload);

static NSEvent *lastMouseDownEvent = nil;

static inline void SetupEventMonitor() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        [NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskLeftMouseDown handler:^NSEvent *(NSEvent *event) {
            if (lastMouseDownEvent != event) {
                [lastMouseDownEvent release];
                lastMouseDownEvent = [event retain];
            }
            return event;
        }];
    });
}

static NSWindow *agentWindow = nil;
static WKWebView *agentWebView = nil;

static inline void PerformWindowDrag(void) {
    if (agentWindow == nil) return;
    NSEvent *event = [NSApp currentEvent];
    if (event == nil || [event type] != NSEventTypeLeftMouseDown) {
        event = lastMouseDownEvent;
    }
    if (event != nil && [event type] == NSEventTypeLeftMouseDown) {
        [agentWindow performWindowDragWithEvent:event];
    }
}

static id getOrCreateBridgeHandler();

static BOOL isModalActive = NO;
static CGFloat titlebarNoDragWidth = 115.0;

static Class getOrCreateTitleBarDragViewClass() {
    Class cls = objc_getClass("ShuffleAgentTitleBarDragView");
    if (!cls) {
        cls = objc_allocateClassPair([NSView class], "ShuffleAgentTitleBarDragView", 0);

        // mouseDownCanMoveWindow -> returns YES
        BOOL (^canMoveBlock)(id) = ^BOOL(id self) {
            return YES;
        };
        class_addMethod(cls, sel_registerName("mouseDownCanMoveWindow"), imp_implementationWithBlock(canMoveBlock), "c@:");

        // hitTest:
        NSView* (^hitTestBlock)(id, NSPoint) = ^NSView*(id self, NSPoint point) {
            if (isModalActive) {
                return nil;
            }
            NSPoint local = [self convertPoint:point fromView:[self superview]];
            if (!NSPointInRect(local, [self bounds])) {
                return nil;
            }
            if (local.x <= titlebarNoDragWidth) {
                return nil;
            }
            return self;
        };
        class_addMethod(cls, sel_registerName("hitTest:"), imp_implementationWithBlock(hitTestBlock), "@@:{CGPoint=dd}");

        // mouseDown:
        void (^mouseDownBlock)(id, NSEvent *) = ^(id self, NSEvent *event) {
            if ([event clickCount] == 2) {
                [[self window] zoom:nil];
                return;
            }
            [[self window] performWindowDragWithEvent:event];
        };
        class_addMethod(cls, sel_registerName("mouseDown:"), imp_implementationWithBlock(mouseDownBlock), "v@:@");

        // windowDidResize:
        void (^resizeNotificationBlock)(id, NSNotification *) = ^(id self, NSNotification *notif) {
            if ([self superview] != nil) {
                NSRect r = [[self superview] bounds];
                [self setFrame:NSMakeRect(0, r.size.height - 38, r.size.width, 38)];
            }
        };
        class_addMethod(cls, sel_registerName("windowDidResize:"), imp_implementationWithBlock(resizeNotificationBlock), "v@:@");

        // viewDidMoveToWindow
        void (^moveBlock)(id) = ^(id self) {
            struct objc_super sup = { .receiver = self, .super_class = [NSView class] };
            void (*superViewDidMoveToWindow)(struct objc_super *, SEL) = (void *)objc_msgSendSuper;
            superViewDidMoveToWindow(&sup, sel_registerName("viewDidMoveToWindow"));

            [[NSNotificationCenter defaultCenter] removeObserver:self name:NSWindowDidResizeNotification object:nil];
            if ([self window] != nil) {
                [[NSNotificationCenter defaultCenter] addObserver:self
                                                         selector:sel_registerName("windowDidResize:")
                                                             name:NSWindowDidResizeNotification
                                                           object:[self window]];
            }
        };
        class_addMethod(cls, sel_registerName("viewDidMoveToWindow"), imp_implementationWithBlock(moveBlock), "v@:");

        // resizeWithOldSuperviewSize:
        void (^superviewResizeBlock)(id, NSSize) = ^(id self, NSSize oldSize) {
            struct objc_super sup = { .receiver = self, .super_class = [NSView class] };
            void (*superResize)(struct objc_super *, SEL, NSSize) = (void *)objc_msgSendSuper;
            superResize(&sup, sel_registerName("resizeWithOldSuperviewSize:"), oldSize);

            if ([self superview] != nil) {
                NSRect r = [[self superview] bounds];
                [self setFrame:NSMakeRect(0, r.size.height - 38, r.size.width, 38)];
            }
        };
        class_addMethod(cls, sel_registerName("resizeWithOldSuperviewSize:"), imp_implementationWithBlock(superviewResizeBlock), "v@:{CGSize=dd}");

        // dealloc
        void (^deallocBlock)(id) = ^(id self) {
            [[NSNotificationCenter defaultCenter] removeObserver:self];
            struct objc_super sup = { .receiver = self, .super_class = [NSView class] };
            void (*superDealloc)(struct objc_super *, SEL) = (void *)objc_msgSendSuper;
            superDealloc(&sup, sel_registerName("dealloc"));
        };
        class_addMethod(cls, sel_registerName("dealloc"), imp_implementationWithBlock(deallocBlock), "v@:");

        objc_registerClassPair(cls);
    }
    return cls;
}

static id getOrCreateBridgeHandler() {
    Class cls = objc_getClass("ShuffleAgentBridgeHandler");
    if (!cls) {
        cls = objc_allocateClassPair([NSObject class], "ShuffleAgentBridgeHandler", 0);
        class_addProtocol(cls, objc_getProtocol("WKScriptMessageHandlerWithReply"));
        class_addProtocol(cls, objc_getProtocol("WKScriptMessageHandler"));

        // Direct fast-path handler for windowDrag (fire-and-forget WKScriptMessageHandler)
        void (^dragBlock)(id, WKUserContentController *, WKScriptMessage *) =
            ^(id self, WKUserContentController *ucc, WKScriptMessage *msg) {
                PerformWindowDrag();
            };
        SEL dragSel = sel_registerName("userContentController:didReceiveScriptMessage:");
        IMP dragImp = imp_implementationWithBlock(dragBlock);
        class_addMethod(cls, dragSel, dragImp, "v@:@@");

        // General bridge handler with reply
        void (^block)(id, WKUserContentController *, WKScriptMessage *, void (^)(id, NSString *)) =
            ^(id self, WKUserContentController *ucc, WKScriptMessage *msg, void (^reply)(id, NSString *)) {
                NSString *action = @"";
                NSString *payload = @"";
                if ([msg.body isKindOfClass:[NSDictionary class]]) {
                    NSDictionary *dict = (NSDictionary *)msg.body;
                    action = [dict objectForKey:@"action"] ?: @"";
                    id p = [dict objectForKey:@"payload"];
                    if ([p isKindOfClass:[NSString class]]) {
                        payload = (NSString *)p;
                    } else if (p != nil) {
                        NSData *data = [NSJSONSerialization dataWithJSONObject:p options:0 error:nil];
                        if (data) {
                            payload = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                        }
                    }
                }

                // Fast-path handlers executed immediately on the main thread
                if ([action isEqualToString:@"setTitlebarNoDragWidth"]) {
                    CGFloat w = [payload doubleValue];
                    if (w > 0 && w < 500) {
                        titlebarNoDragWidth = w;
                    }
                    reply(@"", nil);
                    return;
                }

                if ([action isEqualToString:@"setModalActive"]) {
                    isModalActive = [payload isEqualToString:@"1"] || [payload isEqualToString:@"true"];
                    reply(@"", nil);
                    return;
                }

                if ([action isEqualToString:@"windowAction"] || [action isEqualToString:@"drag"]) {
                    if ([payload isEqualToString:@"close"] || [payload isEqualToString:@"exit"]) {
                        if (agentWindow) [agentWindow orderOut:nil];
                    } else if ([payload isEqualToString:@"minimize"] || [payload isEqualToString:@"lower"]) {
                        if (agentWindow) [agentWindow miniaturize:nil];
                    } else if ([payload isEqualToString:@"maximize"] || [payload isEqualToString:@"expand"]) {
                        if (agentWindow) [agentWindow zoom:nil];
                    } else if ([payload isEqualToString:@"drag"] || [action isEqualToString:@"drag"]) {
                        PerformWindowDrag();
                    }
                    reply(@"", nil);
                    return;
                }

                NSString *act = [action copy];
                NSString *pay = [payload copy];

                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    char *res = HandleBridgeAction((char *)[act UTF8String], (char *)[pay UTF8String]);
                    NSString *respStr = res ? [NSString stringWithUTF8String:res] : @"";
                    if (res) free(res);

                    dispatch_async(dispatch_get_main_queue(), ^{
                        reply(respStr, nil);
                    });
                });
            };

        SEL sel = sel_registerName("userContentController:didReceiveScriptMessage:replyHandler:");
        IMP imp = imp_implementationWithBlock(block);
        class_addMethod(cls, sel, imp, "v@:@@@?");
        objc_registerClassPair(cls);
    }
    return [[cls alloc] init];
}

static NSImage *globalAppIcon = nil;

static inline void SetupAppMenu(const char *appName) {
    NSString *name = appName ? [NSString stringWithUTF8String:appName] : @"Shuffle Agent";
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([NSApp mainMenu] == nil || [[NSApp mainMenu] numberOfItems] == 0) {
            NSMenu *menubar = [[NSMenu alloc] init];
            NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
            [menubar addItem:appMenuItem];
            [NSApp setMainMenu:menubar];

            NSMenu *appMenu = [[NSMenu alloc] initWithTitle:name];
            [appMenuItem setTitle:name];

            NSMenuItem *hideItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Hide %@", name]
                                                              action:@selector(hide:)
                                                       keyEquivalent:@"h"];
            [appMenu addItem:hideItem];

            NSMenuItem *hideOthers = [[NSMenuItem alloc] initWithTitle:@"Hide Others"
                                                                action:@selector(hideOtherApplications:)
                                                         keyEquivalent:@"h"];
            [hideOthers setKeyEquivalentModifierMask:(NSEventModifierFlagOption | NSEventModifierFlagCommand)];
            [appMenu addItem:hideOthers];

            NSMenuItem *showAll = [[NSMenuItem alloc] initWithTitle:@"Show All"
                                                             action:@selector(unhideAllApplications:)
                                                      keyEquivalent:@""];
            [appMenu addItem:showAll];

            [appMenu addItem:[NSMenuItem separatorItem]];

            NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Quit %@", name]
                                                              action:@selector(terminate:)
                                                       keyEquivalent:@"q"];
            [appMenu addItem:quitItem];
            [appMenuItem setSubmenu:appMenu];

            // Edit Menu for Cut, Copy, Paste, Select All (Cmd+A), Undo, Redo
            NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
            [menubar addItem:editMenuItem];
            NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
            [editMenuItem setTitle:@"Edit"];

            [editMenu addItemWithTitle:@"Undo" action:@selector(undo:) keyEquivalent:@"z"];
            NSMenuItem *redoItem = [editMenu addItemWithTitle:@"Redo" action:@selector(redo:) keyEquivalent:@"Z"];
            [redoItem setKeyEquivalentModifierMask:(NSEventModifierFlagShift | NSEventModifierFlagCommand)];
            [editMenu addItem:[NSMenuItem separatorItem]];
            [editMenu addItemWithTitle:@"Cut" action:@selector(cut:) keyEquivalent:@"x"];
            [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
            [editMenu addItemWithTitle:@"Paste" action:@selector(paste:) keyEquivalent:@"v"];
            [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
            [editMenuItem setSubmenu:editMenu];

            // Window Menu for Minimize, Zoom, Close
            NSMenuItem *windowMenuItem = [[NSMenuItem alloc] init];
            [menubar addItem:windowMenuItem];
            NSMenu *windowMenu = [[NSMenu alloc] initWithTitle:@"Window"];
            [windowMenuItem setTitle:@"Window"];
            [windowMenu addItemWithTitle:@"Minimize" action:@selector(performMiniaturize:) keyEquivalent:@"m"];
            [windowMenu addItemWithTitle:@"Zoom" action:@selector(performZoom:) keyEquivalent:@""];
            [windowMenu addItem:[NSMenuItem separatorItem]];
            [windowMenu addItemWithTitle:@"Close Window" action:@selector(performClose:) keyEquivalent:@"w"];
            [windowMenuItem setSubmenu:windowMenu];
        }
    });
}

static inline void ApplyAppIdentity(const char *appName, const void *iconData, int iconLen) {
    NSString *name = appName ? [NSString stringWithUTF8String:appName] : @"Shuffle Agent";
    [[NSProcessInfo processInfo] setProcessName:name];

    if (iconData != NULL && iconLen > 0) {
        NSData *data = [NSData dataWithBytes:iconData length:iconLen];
        dispatch_async(dispatch_get_main_queue(), ^{
            globalAppIcon = [[NSImage alloc] initWithData:data];
            if (globalAppIcon != nil) {
                [NSApp setApplicationIconImage:globalAppIcon];
                [[NSApp dockTile] display];
            }
        });
    }
    SetupAppMenu(appName);
}

static void ensureAgentWindowCreated(const char *title, int width, int height, const char *htmlContent) {
    SetupEventMonitor();
    if (agentWindow != nil) return;

    CGFloat w = (width > 0) ? (CGFloat)width : 950;
    CGFloat h = (height > 0) ? (CGFloat)height : 700;
    NSRect frame = NSMakeRect(200, 200, w, h);
    NSUInteger style = NSWindowStyleMaskTitled |
                       NSWindowStyleMaskFullSizeContentView |
                       NSWindowStyleMaskClosable |
                       NSWindowStyleMaskMiniaturizable |
                       NSWindowStyleMaskResizable;
    agentWindow = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    NSString *titleStr = title ? [NSString stringWithUTF8String:title] : @"Shuffle Agent";
    [agentWindow setTitle:titleStr];
    [agentWindow setTitleVisibility:NSWindowTitleHidden];
    [agentWindow setTitlebarAppearsTransparent:YES];
    [[agentWindow standardWindowButton:NSWindowCloseButton] setHidden:YES];
    [[agentWindow standardWindowButton:NSWindowMiniaturizeButton] setHidden:YES];
    [[agentWindow standardWindowButton:NSWindowZoomButton] setHidden:YES];
    [agentWindow setMovable:YES];
    [agentWindow setMovableByWindowBackground:YES];
    [agentWindow setReleasedWhenClosed:NO];
    [agentWindow setMinSize:NSMakeSize(640, 480)];
    [agentWindow center];

    agentWindow.backgroundColor = [NSColor colorWithCalibratedRed:0.035 green:0.051 blue:0.086 alpha:1.0];

    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];

    NSString *bridgeScript = @""
        "window.bridgeCall = function(action, payload) {"
        "    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.bridge) {"
        "        return window.webkit.messageHandlers.bridge.postMessage({ action: action, payload: payload });"
        "    }"
        "    return Promise.reject('Bridge not available');"
        "};"
        "window.startWindowDrag = function() {"
        "    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.windowDrag) {"
        "        window.webkit.messageHandlers.windowDrag.postMessage('');"
        "    } else if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.bridge) {"
        "        window.webkit.messageHandlers.bridge.postMessage({ action: 'windowAction', payload: 'drag' });"
        "    }"
        "};"
        "window.setTitlebarNoDragWidth = function(width) {"
        "    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.bridge) {"
        "        window.webkit.messageHandlers.bridge.postMessage({ action: 'setTitlebarNoDragWidth', payload: String(width) });"
        "    }"
        "};"
        "window.setModalActive = function(active) {"
        "    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.bridge) {"
        "        window.webkit.messageHandlers.bridge.postMessage({ action: 'setModalActive', payload: active ? '1' : '0' });"
        "    }"
        "};"
        "window.getInitialState = function() { return window.bridgeCall('getInitialState', ''); };"
        "window.listProjects = function() { return window.bridgeCall('listProjects', ''); };"
        "window.selectProject = function(path) { return window.bridgeCall('selectProject', path); };"
        "window.setPermissionPolicy = function(policy) { return window.bridgeCall('setPermissionPolicy', policy); };"
        "window.runPrompt = function(prompt, bypass, convId) { return window.bridgeCall('runPrompt', JSON.stringify({prompt: prompt, bypass: bypass, conversation_id: convId || ''})); };"
        "window.respondApproval = function(id, approved) { return window.bridgeCall('respondApproval', JSON.stringify({id: id, approved: approved})); };"
        "window.respondApprovalWithOptions = function(id, option, commandPrefix, scope, scopeId) { return window.bridgeCall('respondApprovalWithOptions', JSON.stringify({id: id, option: option, commandPrefix: commandPrefix, scope: scope, scopeId: scopeId})); };"
        "window.getApprovalRules = function() { return window.bridgeCall('getApprovalRules', ''); };"
        "window.addApprovalRule = function(rule) { return window.bridgeCall('addApprovalRule', typeof rule === 'string' ? rule : JSON.stringify(rule)); };"
        "window.revokeApprovalRule = function(id) { return window.bridgeCall('revokeApprovalRule', id); };"
        "window.clearApprovalRules = function() { return window.bridgeCall('clearApprovalRules', ''); };"
        "window.setPinnedConversations = function(pinned) { return window.bridgeCall('setPinnedConversations', typeof pinned === 'string' ? pinned : JSON.stringify(pinned)); };"
        "window.takeScreenshot = function() { return window.bridgeCall('takeScreenshot', ''); };"
        "window.inspectUI = function() { return window.bridgeCall('inspectUI', ''); };"
        "window.requestOSPermission = function(perm) { return window.bridgeCall('requestOSPermission', perm); };"
        "window.updateAuth = function(authData) { return window.bridgeCall('updateAuth', typeof authData === 'string' ? authData : JSON.stringify(authData)); };"
        "window.setAiConfig = function(url, key, policy, model) { return window.bridgeCall('setAiConfig', JSON.stringify({url: url, key: key, permission_policy: policy || '', model: model || ''})); };"
        "window.startOAuthLogin = function(url) { return window.bridgeCall('startOAuthLogin', url || ''); };"
        "window.setOAuthToken = function(token, org, env) { return window.bridgeCall('setOAuthToken', JSON.stringify({token: token, org: org, env: env})); };"
        "window.windowAction = function(act) { return window.bridgeCall('windowAction', act); };"
        "window.chooseDirectory = function() { return window.bridgeCall('chooseDirectory', ''); };"
        "window.chooseFile = function() { return window.bridgeCall('chooseFile', ''); };"
        "window.clearHistory = function() { return window.bridgeCall('clearHistory', ''); };"
        "window.saveAllSettings = function(settings) { return window.bridgeCall('saveAllSettings', typeof settings === 'string' ? settings : JSON.stringify(settings)); };"
        "window.setProjectPermissions = function(project, perms) { return window.bridgeCall('setProjectPermissions', JSON.stringify({project: project, permissions: perms})); };";

    WKUserScript *userScript = [[WKUserScript alloc] initWithSource:bridgeScript
                                                      injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                                    forMainFrameOnly:YES];
    [config.userContentController addUserScript:userScript];

    @try {
        id bridgeHandler = getOrCreateBridgeHandler();
        [config.userContentController addScriptMessageHandlerWithReply:bridgeHandler
                                                          contentWorld:[WKContentWorld pageWorld]
                                                                  name:@"bridge"];
        [config.userContentController addScriptMessageHandler:bridgeHandler
                                                 contentWorld:[WKContentWorld pageWorld]
                                                         name:@"windowDrag"];
    } @catch (NSException *e) {
        NSLog(@"[ERROR] Failed to register WebKit bridge: %@", e);
    }

    agentWebView = [[WKWebView alloc] initWithFrame:[agentWindow.contentView bounds] configuration:config];
    [agentWebView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    [agentWebView setValue:@NO forKey:@"drawsBackground"];
    [agentWindow.contentView addSubview:agentWebView];

    // Transparent native topbar overlay: guarantees instantaneous hardware window dragging
    NSRect titleFrame = NSMakeRect(0, [agentWindow.contentView bounds].size.height - 38, [agentWindow.contentView bounds].size.width, 38);
    Class dragClass = getOrCreateTitleBarDragViewClass();
    NSView *dragView = [[dragClass alloc] initWithFrame:titleFrame];
    [dragView setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
    [agentWindow.contentView addSubview:dragView positioned:NSWindowAbove relativeTo:agentWebView];

    if (htmlContent != NULL && strlen(htmlContent) > 0) {
        NSString *html = [NSString stringWithUTF8String:htmlContent];
        [agentWebView loadHTMLString:html baseURL:nil];
    }
}

static inline void ShowAgentWindow(const char *title, int width, int height, char *htmlContent) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (agentWindow == nil) {
            ensureAgentWindowCreated(title, width, height, htmlContent);
        }
        if (htmlContent != NULL) {
            free(htmlContent);
        }
        if (agentWindow != nil) {
            [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
            if (globalAppIcon != nil) {
                [NSApp setApplicationIconImage:globalAppIcon];
                [[NSApp dockTile] display];
            }
            SetupAppMenu(title);
            [agentWindow setIsVisible:YES];
            [agentWindow makeKeyAndOrderFront:nil];
            if (agentWebView != nil) {
                [agentWindow makeFirstResponder:agentWebView];
            }
            [agentWindow orderFrontRegardless];
            [NSApp activateIgnoringOtherApps:YES];
        }
    });
}

static inline void HideAgentWindow() {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (agentWindow != nil) {
            [agentWindow orderOut:nil];
        }
    });
}

static inline void WindowAction(const char *action) {
    if (action == NULL) return;
    NSString *act = [NSString stringWithUTF8String:action];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (agentWindow == nil) return;
        if ([act isEqualToString:@"close"] || [act isEqualToString:@"exit"]) {
            [agentWindow orderOut:nil];
        } else if ([act isEqualToString:@"minimize"] || [act isEqualToString:@"lower"]) {
            [agentWindow miniaturize:nil];
        } else if ([act isEqualToString:@"maximize"] || [act isEqualToString:@"expand"]) {
            [agentWindow zoom:nil];
        } else if ([act isEqualToString:@"drag"]) {
            PerformWindowDrag();
        } else if ([act hasPrefix:@"move:"]) {
            NSArray *parts = [act componentsSeparatedByString:@":"];
            if ([parts count] == 3) {
                CGFloat dx = [[parts objectAtIndex:1] doubleValue];
                CGFloat dy = [[parts objectAtIndex:2] doubleValue];
                NSPoint origin = [agentWindow frame].origin;
                origin.x += dx;
                origin.y -= dy;
                [agentWindow setFrameOrigin:origin];
            }
        }
    });
}

static inline void EvaluateJSInAgentWindow(const char *jsCode) {
    if (jsCode == NULL) return;
    NSString *js = [NSString stringWithUTF8String:jsCode];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (agentWebView != nil) {
            [agentWebView evaluateJavaScript:js completionHandler:nil];
        }
    });
}

static char* ChooseFolderDialog(const char *title, const char *prompt) {
    __block char *result = NULL;
    dispatch_sync(dispatch_get_main_queue(), ^{
        NSOpenPanel *panel = [NSOpenPanel openPanel];
        [panel setCanChooseFiles:NO];
        [panel setCanChooseDirectories:YES];
        [panel setAllowsMultipleSelection:NO];
        [panel setPrompt:(prompt && strlen(prompt) > 0) ? [NSString stringWithUTF8String:prompt] : @"Select"];
        [panel setMessage:(title && strlen(title) > 0) ? [NSString stringWithUTF8String:title] : @"Select Directory"];
        if (agentWindow != nil) {
            [panel setLevel:[agentWindow level] + 1];
        } else {
            [panel setLevel:NSFloatingWindowLevel];
        }
        [NSApp activateIgnoringOtherApps:YES];
        if ([panel runModal] == NSModalResponseOK) {
            NSURL *url = [[panel URLs] firstObject];
            if (url != nil) {
                const char *path = [[url path] UTF8String];
                if (path != NULL) {
                    result = strdup(path);
                }
            }
        }
    });
    return result;
}

static char* ChooseFileDialog(const char *title, const char *prompt) {
    __block char *result = NULL;
    dispatch_sync(dispatch_get_main_queue(), ^{
        NSOpenPanel *panel = [NSOpenPanel openPanel];
        [panel setCanChooseFiles:YES];
        [panel setCanChooseDirectories:NO];
        [panel setAllowsMultipleSelection:NO];
        [panel setPrompt:(prompt && strlen(prompt) > 0) ? [NSString stringWithUTF8String:prompt] : @"Select"];
        [panel setMessage:(title && strlen(title) > 0) ? [NSString stringWithUTF8String:title] : @"Select File"];
        if (agentWindow != nil) {
            [panel setLevel:[agentWindow level] + 1];
        } else {
            [panel setLevel:NSFloatingWindowLevel];
        }
        [NSApp activateIgnoringOtherApps:YES];
        if ([panel runModal] == NSModalResponseOK) {
            NSURL *url = [[panel URLs] firstObject];
            if (url != nil) {
                const char *path = [[url path] UTF8String];
                if (path != NULL) {
                    result = strdup(path);
                }
            }
        }
    });
    return result;
}

static inline int IsAgentWindowVisible() {
    if (agentWindow == nil) return 0;
    return [agentWindow isVisible] ? 1 : 0;
}

static inline int IsAgentWindowCreated() {
    return agentWindow != nil ? 1 : 0;
}
*/
import "C"

import (
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
func HandleBridgeAction(cAction *C.char, cPayload *C.char) *C.char {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ERROR] Recovered from panic in HandleBridgeAction: %v", r)
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
