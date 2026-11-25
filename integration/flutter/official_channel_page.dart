import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:life_web_bridge/life_web_bridge.dart';
import 'package:webview_flutter/webview_flutter.dart';

/// Stock webview_flutter integration.
///
/// The official [JavaScriptChannel] callback exposes only [JavaScriptMessage.message];
/// it has no trusted origin or frame field. Therefore [IncomingTransportMessage.frame]
/// is intentionally null here. Critical policies must require
/// [SourceAssurance.nativeFrameMetadata] and be served by the custom native
/// adapter in source_aware_method_bridge.dart.
class SecureActivityWebView extends StatefulWidget {
  const SecureActivityWebView({
    super.key,
    required this.webViewId,
    required this.uri,
    required this.coordinator,
    this.trustedMainOrigins = const <String>{},
  });

  final String webViewId;
  final Uri uri;
  final WebBridgeCoordinator coordinator;
  final Set<String> trustedMainOrigins;

  @override
  State<SecureActivityWebView> createState() => _SecureActivityWebViewState();
}

class _SecureActivityWebViewState extends State<SecureActivityWebView> {
  late final WebViewController controller;

  @override
  void initState() {
    super.initState();

    controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..addJavaScriptChannel(
        'LifeBridge',
        onMessageReceived: (JavaScriptMessage message) {
          // Do not read origin/isMainFrame from message.message: page JS controls
          // those fields. frame: null forces ticket/native-metadata authentication.
          unawaited(() async {
            final BridgeResponse response = await widget.coordinator.onMessage(
              IncomingTransportMessage(
                webViewId: widget.webViewId,
                body: message.message,
                frame: null,
              ),
            );

            // The injected router resolves Promise/callback ids. If the legacy
            // page uses another global reply convention, also evaluate
            // response.toLegacyJavaScript(...) with the matching dispatcher.
            await controller.runJavaScript(response.toJavaScript());
          }());
        },
      )
      ..setNavigationDelegate(
        NavigationDelegate(
          onNavigationRequest: (NavigationRequest request) {
            if (request.isMainFrame != true) {
              return NavigationDecision.navigate;
            }

            // Observing a request is not yet a commit. This only starts/rotates
            // the provisional navigation generation.
            widget.coordinator.onNavigation(
              widget.webViewId,
              NavigationProvisionalStart(request.url),
            );
            return NavigationDecision.navigate;
          },
          onPageStarted: (String url) {
            widget.coordinator.onNavigation(
              widget.webViewId,
              NavigationProvisionalStart(url),
            );

            // Best-effort fallback. For the strongest early-injection defense,
            // add WebBridgeBootstrap.kScript as a native at-document-start user
            // script on iOS and Android.
            unawaited(
              controller.runJavaScript(
                WebBridgeBootstrap.build(
                  outboundChannelName: 'LifeBridge',
                  awaitDocumentTicket: true,
                ),
              ),
            );
          },
          onUrlChange: (UrlChange change) {
            final String? url = change.url;
            if (url == null) return;

            // Redirect/history URL changes are still not trust establishment.
            // The state machine keeps the document provisional until commit or
            // the platform's finished reconciliation.
            widget.coordinator.onNavigation(
              widget.webViewId,
              NavigationRedirected(url),
            );
          },
          onPageFinished: (String url) async {
            final DocumentTicket? ticket = widget.coordinator.onNavigation(
              widget.webViewId,
              NavigationFinished(url),
            );

            if (ticket != null) {
              final String js = 'window.__lifeBridgeSetTicket && '
                  'window.__lifeBridgeSetTicket(${jsonEncode(ticket.token)});';
              await controller.runJavaScript(js);
            }
          },
          onWebResourceError: (WebResourceError error) {
            // Map main-frame failures to NavigationFailed in the native
            // adapter/version-specific API. Do not revoke the active ticket for
            // an iframe/image/script resource error.
          },
        ),
      )
      ..loadRequest(widget.uri);
  }

  @override
  void dispose() {
    widget.coordinator.disposeWebView(widget.webViewId);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return WebViewWidget(controller: controller);
  }
}

/// Sends [BridgeResponse] JSON to the injected `__lifeBridgeReceive` router.
class WebViewControllerResponseSink implements BridgeResponseSink {
  WebViewControllerResponseSink(this.controller);

  final WebViewController controller;

  @override
  Future<void> send(
    BridgeResponse response, {
    required String webViewId,
    String? replyToken,
  }) {
    return controller.runJavaScript(response.toJavaScript());
  }
}
