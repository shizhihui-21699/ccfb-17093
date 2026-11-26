/// The host seam.
///
/// The guard never talks to `webview_flutter` directly. It only needs three
/// things from the host, and each maps to a platform capability that is
/// **main-frame scoped** by definition:
///
/// | port method            | Android                     | iOS                          |
/// |------------------------|-----------------------------|------------------------------|
/// | [evaluateMainFrame]    | `WebView.evaluateJavascript`| `WKWebView.evaluateJavaScript`|
/// | [injectMainFrame]      | `WebView.evaluateJavascript`| `WKWebView.evaluateJavaScript`|
/// | [installBootstrap]     | `WebViewCompat.addDocumentStartJavaScript` | `WKUserScript` at `documentStart`, `forMainFrameOnly: false` |
///
/// The main-frame scoping of the evaluation APIs is the load-bearing fact
/// behind the whole design: a script answer that native asks for can only
/// come from the top document, so an ad iframe cannot answer on its behalf.
library;

import 'dart:async';

/// Host abstraction. Implementations live in `lib/src/adapters/` and are
/// written against the concrete plugin in the app.
abstract interface class PlatformPort {
  /// Short platform name for diagnostics (`android`, `ios`, `test`).
  String get name;

  /// Evaluates [script] in the **top-level frame only** and returns its value.
  ///
  /// Must throw [TimeoutException] (or return null) if the platform cannot
  /// answer; the guard treats both as "not ready" and denies.
  Future<Object?> evaluateMainFrame(String script);

  /// Evaluates [script] in the top-level frame without waiting for a value.
  /// Used for fire-and-forget delivery of replies.
  Future<void> injectMainFrame(String script);

  /// Installs [script] so it runs at **document start in every frame**, before
  /// any page script. Returns false when the platform cannot guarantee that
  /// (for example because the plugin does not expose document-start
  /// injection). The guard does not depend on this for security — only for
  /// legacy-page compatibility — but a false result is logged at startup.
  Future<bool> installBootstrap(String script);
}
