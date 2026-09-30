//go:build darwin

#import "darwin.h"
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#include <ApplicationServices/ApplicationServices.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>

extern char* HandleBridgeAction(char* action, char* payload);

static NSEvent *lastMouseDownEvent = nil;

static inline void SetupEventMonitor(void) {
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

static BOOL isModalActive = NO;
static CGFloat titlebarNoDragWidth = 115.0;

@interface ShuffleAgentTitleBarDragView : NSView
@end

@implementation ShuffleAgentTitleBarDragView

- (BOOL)mouseDownCanMoveWindow {
    return YES;
}

- (NSView *)hitTest:(NSPoint)point {
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
}

- (void)mouseDown:(NSEvent *)event {
    if ([event clickCount] == 2) {
        [[self window] zoom:nil];
        return;
    }
    [[self window] performWindowDragWithEvent:event];
}

- (void)windowDidResize:(NSNotification *)notif {
    if ([self superview] != nil) {
        NSRect r = [[self superview] bounds];
        [self setFrame:NSMakeRect(0, r.size.height - 38, r.size.width, 38)];
    }
}

- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    [[NSNotificationCenter defaultCenter] removeObserver:self name:NSWindowDidResizeNotification object:nil];
    if ([self window] != nil) {
        [[NSNotificationCenter defaultCenter] addObserver:self
                                                 selector:@selector(windowDidResize:)
                                                     name:NSWindowDidResizeNotification
                                                   object:[self window]];
    }
}

- (void)resizeWithOldSuperviewSize:(NSSize)oldSize {
    [super resizeWithOldSuperviewSize:oldSize];
    if ([self superview] != nil) {
        NSRect r = [[self superview] bounds];
        [self setFrame:NSMakeRect(0, r.size.height - 38, r.size.width, 38)];
    }
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [super dealloc];
}
@end

@interface ShuffleAgentBridgeHandler : NSObject <WKScriptMessageHandler, WKScriptMessageHandlerWithReply>
@end

@implementation ShuffleAgentBridgeHandler

- (void)userContentController:(WKUserContentController *)ucc didReceiveScriptMessage:(WKScriptMessage *)msg {
    PerformWindowDrag();
}

- (void)userContentController:(WKUserContentController *)ucc
      didReceiveScriptMessage:(WKScriptMessage *)msg
                 replyHandler:(void (^)(id, NSString *))reply {
    NSString *action = @"";
    NSString *payload = @"";
    if ([msg.body isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)msg.body;
        id a = [dict objectForKey:@"action"];
        if ([a isKindOfClass:[NSString class]]) {
            action = (NSString *)a;
        }
        id p = [dict objectForKey:@"payload"];
        if ([p isKindOfClass:[NSString class]]) {
            payload = (NSString *)p;
        } else if (p != nil) {
            NSData *data = [NSJSONSerialization dataWithJSONObject:p options:0 error:nil];
            if (data) {
                payload = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
            }
        }
    }

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
            [act release];
            [pay release];
        });
    });
}
@end

static NSImage *globalAppIcon = nil;

static inline void SetupAppMenu(const char *appName) {
    NSString *name = (appName && strlen(appName) > 0) ? [[NSString stringWithUTF8String:appName] retain] : [@"Shuffle Agent" retain];
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
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

                // Edit menu (Cmd+C, Cmd+V, Cmd+X, Cmd+A, Cmd+Z)
                NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
                [menubar addItem:editMenuItem];

                NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
                [editMenuItem setTitle:@"Edit"];

                NSMenuItem *undoItem = [[NSMenuItem alloc] initWithTitle:@"Undo" action:@selector(undo:) keyEquivalent:@"z"];
                [editMenu addItem:undoItem];

                NSMenuItem *redoItem = [[NSMenuItem alloc] initWithTitle:@"Redo" action:@selector(redo:) keyEquivalent:@"Z"];
                [editMenu addItem:redoItem];

                [editMenu addItem:[NSMenuItem separatorItem]];

                NSMenuItem *cutItem = [[NSMenuItem alloc] initWithTitle:@"Cut" action:@selector(cut:) keyEquivalent:@"x"];
                [editMenu addItem:cutItem];

                NSMenuItem *copyItem = [[NSMenuItem alloc] initWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
                [editMenu addItem:copyItem];

                NSMenuItem *pasteItem = [[NSMenuItem alloc] initWithTitle:@"Paste" action:@selector(paste:) keyEquivalent:@"v"];
                [editMenu addItem:pasteItem];

                NSMenuItem *selectAllItem = [[NSMenuItem alloc] initWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
                [editMenu addItem:selectAllItem];

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
        } @catch (NSException *ex) {
            NSLog(@"[ERROR] Caught exception in SetupAppMenu: %@", ex);
        } @finally {
            [name release];
        }
    });
}

void ApplyAppIdentity(const char *appName, const void *iconData, int iconLen) {
    NSString *name = (appName && strlen(appName) > 0) ? [[NSString stringWithUTF8String:appName] retain] : [@"Shuffle Agent" retain];
    NSData *data = (iconData != NULL && iconLen > 0) ? [[NSData dataWithBytes:iconData length:iconLen] retain] : nil;

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            [[NSProcessInfo processInfo] setProcessName:name];
            if (data != nil) {
                if (globalAppIcon != nil) {
                    [globalAppIcon release];
                }
                globalAppIcon = [[NSImage alloc] initWithData:data];
                if (globalAppIcon != nil) {
                    [NSApp setApplicationIconImage:globalAppIcon];
                    [[NSApp dockTile] display];
                }
            }
            SetupAppMenu([name UTF8String]);
        } @catch (NSException *ex) {
            NSLog(@"[ERROR] Caught exception in ApplyAppIdentity: %@", ex);
        } @finally {
            [name release];
            if (data) [data release];
        }
    });
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
    NSString *titleStr = (title && strlen(title) > 0) ? [NSString stringWithUTF8String:title] : @"Shuffle Agent";
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
        "window.listConversations = function() { return window.bridgeCall('listConversations', ''); };"
        "window.getConversation = function(id) { return window.bridgeCall('getConversation', id); };"
        "window.saveConversation = function(conv) { return window.bridgeCall('saveConversation', typeof conv === 'string' ? conv : JSON.stringify(conv)); };"
        "window.deleteConversation = function(id) { return window.bridgeCall('deleteConversation', id); };"
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
        "window.setProjectPermissions = function(project, perms) { return window.bridgeCall('setProjectPermissions', JSON.stringify({project: project, permissions: perms})); };"
        "window.listSkills = function(proj) { return window.bridgeCall('listSkills', proj || ''); };"
        "window.injectSkillFile = function(path) { return window.bridgeCall('injectSkillFile', JSON.stringify({path: path || ''})); };"
        "window.injectSkill = function(skill) { return window.bridgeCall('injectSkill', typeof skill === 'string' ? skill : JSON.stringify(skill)); };"
        "window.removeInjectedSkill = function(name) { return window.bridgeCall('removeInjectedSkill', JSON.stringify({name: name})); };"
        "window.clearInjectedSkills = function() { return window.bridgeCall('clearInjectedSkills', ''); };"
        "window.getProjectContext = function(proj) { return window.bridgeCall('getProjectContext', proj || ''); };";

    WKUserScript *userScript = [[WKUserScript alloc] initWithSource:bridgeScript
                                                      injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                                    forMainFrameOnly:YES];
    [config.userContentController addUserScript:userScript];

    @try {
        ShuffleAgentBridgeHandler *bridgeHandler = [[ShuffleAgentBridgeHandler alloc] init];
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
    ShuffleAgentTitleBarDragView *dragView = [[ShuffleAgentTitleBarDragView alloc] initWithFrame:titleFrame];
    [dragView setAutoresizingMask:(NSViewWidthSizable | NSViewMinYMargin)];
    [agentWindow.contentView addSubview:dragView positioned:NSWindowAbove relativeTo:agentWebView];

    if (htmlContent != NULL && strlen(htmlContent) > 0) {
        NSString *html = [NSString stringWithUTF8String:htmlContent];
        [agentWebView loadHTMLString:html baseURL:nil];
    }
}

void PrewarmAgentWindow(const char *title, int width, int height, char *htmlContent) {
    NSString *titleStr = (title && strlen(title) > 0) ? [[NSString stringWithUTF8String:title] retain] : [@"Shuffle Agent" retain];
    NSString *htmlStr = (htmlContent && strlen(htmlContent) > 0) ? [[NSString stringWithUTF8String:htmlContent] retain] : nil;
    if (htmlContent != NULL) {
        free(htmlContent);
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (agentWindow == nil) {
                ensureAgentWindowCreated([titleStr UTF8String], width, height, htmlStr ? [htmlStr UTF8String] : "");
                [agentWindow orderOut:nil];
            }
        } @catch (NSException *ex) {
            NSLog(@"[ERROR] Caught exception in PrewarmAgentWindow: %@", ex);
        } @finally {
            [titleStr release];
            if (htmlStr) [htmlStr release];
        }
    });
}

void ShowAgentWindow(const char *title, int width, int height, char *htmlContent) {
    NSString *titleStr = (title && strlen(title) > 0) ? [[NSString stringWithUTF8String:title] retain] : [@"Shuffle Agent" retain];
    NSString *htmlStr = (htmlContent && strlen(htmlContent) > 0) ? [[NSString stringWithUTF8String:htmlContent] retain] : nil;
    if (htmlContent != NULL) {
        free(htmlContent);
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (agentWindow == nil) {
                ensureAgentWindowCreated([titleStr UTF8String], width, height, htmlStr ? [htmlStr UTF8String] : "");
            }
            if (agentWindow != nil) {
                [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
                if (globalAppIcon != nil) {
                    [NSApp setApplicationIconImage:globalAppIcon];
                    [[NSApp dockTile] display];
                }
                SetupAppMenu([titleStr UTF8String]);
                [agentWindow setIsVisible:YES];
                [agentWindow makeKeyAndOrderFront:nil];
                if (agentWebView != nil) {
                    [agentWindow makeFirstResponder:agentWebView];
                }
                [agentWindow orderFrontRegardless];
                [NSApp activateIgnoringOtherApps:YES];
            }
        } @catch (NSException *ex) {
            NSLog(@"[ERROR] Caught exception in ShowAgentWindow: %@", ex);
        } @finally {
            [titleStr release];
            if (htmlStr) [htmlStr release];
        }
    });
}

void HideAgentWindow(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (agentWindow != nil) {
                [agentWindow orderOut:nil];
            }
        } @catch (NSException *ex) {
            NSLog(@"[ERROR] Caught exception in HideAgentWindow: %@", ex);
        }
    });
}

void WindowAction(const char *action) {
    if (action == NULL) return;
    NSString *act = [[NSString stringWithUTF8String:action] retain];
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
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
        } @catch (NSException *ex) {
            NSLog(@"[ERROR] Caught exception in WindowAction: %@", ex);
        } @finally {
            [act release];
        }
    });
}

void EvaluateJSInAgentWindow(const char *jsCode) {
    if (jsCode == NULL) return;
    NSString *js = [[NSString stringWithUTF8String:jsCode] retain];
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            if (agentWebView != nil) {
                [agentWebView evaluateJavaScript:js completionHandler:nil];
            }
        } @catch (NSException *ex) {
            NSLog(@"[ERROR] Caught exception in EvaluateJSInAgentWindow: %@", ex);
        } @finally {
            [js release];
        }
    });
}

static inline void runOnMainThreadSync(void (^block)(void)) {
    if ([NSThread isMainThread]) {
        block();
    } else {
        dispatch_sync(dispatch_get_main_queue(), block);
    }
}

char* ChooseFolderDialog(const char *title, const char *prompt) {
    __block char *result = NULL;
    NSString *titleStr = (title && strlen(title) > 0) ? [NSString stringWithUTF8String:title] : @"Select Directory";
    NSString *promptStr = (prompt && strlen(prompt) > 0) ? [NSString stringWithUTF8String:prompt] : @"Select";

    runOnMainThreadSync(^{
        @try {
            NSOpenPanel *panel = [NSOpenPanel openPanel];
            [panel setCanChooseFiles:NO];
            [panel setCanChooseDirectories:YES];
            [panel setAllowsMultipleSelection:NO];
            [panel setPrompt:promptStr];
            [panel setMessage:titleStr];
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
        } @catch (NSException *ex) {
            NSLog(@"[ERROR] Caught exception in ChooseFolderDialog: %@", ex);
        }
    });
    return result;
}

char* ChooseFileDialog(const char *title, const char *prompt) {
    __block char *result = NULL;
    NSString *titleStr = (title && strlen(title) > 0) ? [NSString stringWithUTF8String:title] : @"Select File";
    NSString *promptStr = (prompt && strlen(prompt) > 0) ? [NSString stringWithUTF8String:prompt] : @"Select";

    runOnMainThreadSync(^{
        @try {
            NSOpenPanel *panel = [NSOpenPanel openPanel];
            [panel setCanChooseFiles:YES];
            [panel setCanChooseDirectories:NO];
            [panel setAllowsMultipleSelection:NO];
            [panel setPrompt:promptStr];
            [panel setMessage:titleStr];
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
        } @catch (NSException *ex) {
            NSLog(@"[ERROR] Caught exception in ChooseFileDialog: %@", ex);
        }
    });
    return result;
}

int IsAgentWindowVisible(void) {
    if (agentWindow == nil) return 0;
    return [agentWindow isVisible] ? 1 : 0;
}

int IsAgentWindowCreated(void) {
    return agentWindow != nil ? 1 : 0;
}
