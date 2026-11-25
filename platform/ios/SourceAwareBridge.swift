import Foundation
import WebKit
import Flutter

/// Source-aware iOS bridge.
///
/// Unlike `WKScriptMessage.body`, `WKScriptMessage.frameInfo` is populated by
/// WebKit and is safe to use for origin and main-frame checks. Forward this
/// metadata to Dart; never accept `origin`/`isMainFrame` from the JS body.
///
/// Register one instance per Flutter-managed WebView and use the matching
/// MethodChannel name: `life_web_bridge/source_aware/<webViewId>`.
final class SourceAwareBridge: NSObject, WKScriptMessageHandlerWithReply {
    let webViewId: String
    private let channel: FlutterMethodChannel
    private(set) var topLevelOrigin: String?

    init(webViewId: String, messenger: FlutterBinaryMessenger) {
        self.webViewId = webViewId
        self.channel = FlutterMethodChannel(
            name: "life_web_bridge/source_aware/\(webViewId)",
            binaryMessenger: messenger
        )
        super.init()
    }

    func install(on userContentController: WKUserContentController) {
        // The JS object becomes window.webkit.messageHandlers.LifeSourceBridge.
        userContentController.addScriptMessageHandler(
            self,
            contentWorld: WKContentWorld.page,
            name: "LifeSourceBridge"
        )
    }

    func trackMainFrameNavigation(url: URL?) {
        guard let url = url,
              let scheme = url.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              let host = url.host?.lowercased() else {
            topLevelOrigin = nil
            return
        }

        let port = url.port
        let isDefault = port == nil ||
            (scheme == "https" && port == 443) ||
            (scheme == "http" && port == 80)
        topLevelOrigin = isDefault ? "\(scheme)://\(host)" : "\(scheme)://\(host):\(port!)"
    }

    func userContentController(
        _ userContentController: WKUserContentController,
        didReceive message: WKScriptMessage,
        replyHandler: @escaping (Any?, String?) -> Void
    ) {
        let frame = message.frameInfo
        let origin = canonicalOrigin(from: frame)

        let source: [String: Any] = [
            "origin": origin ?? "",
            "isMainFrame": frame.isMainFrame,
            // The APIs do not expose a full ancestor chain. Supply the native
            // tracked top-level origin when a child-frame policy needs it.
            "ancestors": topLevelOrigin.map { [$0] } ?? []
        ]

        let arguments: [String: Any] = [
            "body": message.body,
            "source": source
        ]

        channel.invokeMethod("bridgeMessage", arguments: arguments) { result in
            if let error = result as? FlutterError {
                replyHandler(nil, error.code)
                return
            }

            // Dart returns a JSON-compatible dictionary. The page response
            // router can also be invoked through evaluateJavaScript.
            replyHandler(result, nil)
        }
    }

    private func canonicalOrigin(from frame: WKFrameInfo) -> String? {
        let securityOrigin = frame.securityOrigin
        if let securityOrigin = securityOrigin,
           !securityOrigin.`protocol`.isEmpty,
           !securityOrigin.host.isEmpty {
            let scheme = securityOrigin.`protocol`.lowercased()
            let host = securityOrigin.host.lowercased()
            let port = securityOrigin.port
            if port > 0,
               !((scheme == "https" && port == 443) ||
                 (scheme == "http" && port == 80)) {
                return "\(scheme)://\(host):\(port)"
            }
            return "\(scheme)://\(host)"
        }

        return frame.request.url.map { url in
            let scheme = url.scheme ?? "https"
            let host = url.host ?? ""
            if let port = url.port {
                return "\(scheme)://\(host):\(port)"
            }
            return "\(scheme)://\(host)"
        }
    }
}
