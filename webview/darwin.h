#ifndef DARWIN_WEBVIEW_H
#define DARWIN_WEBVIEW_H

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

#ifdef __cplusplus
extern "C" {
#endif

void ApplyAppIdentity(const char *appName, const void *iconData, int iconLen);
void PrewarmAgentWindow(const char *title, int width, int height, char *htmlContent);
void ShowAgentWindow(const char *title, int width, int height, char *htmlContent);
void HideAgentWindow(void);
void WindowAction(const char *action);
void EvaluateJSInAgentWindow(const char *jsCode);
char* ChooseFolderDialog(const char *title, const char *prompt);
char* ChooseFileDialog(const char *title, const char *prompt);
int IsAgentWindowVisible(void);
int IsAgentWindowCreated(void);

#ifdef __cplusplus
}
#endif

#endif // DARWIN_WEBVIEW_H
