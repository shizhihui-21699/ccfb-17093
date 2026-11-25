import 'package:flutter/services.dart';
import 'package:life_web_bridge/life_web_bridge.dart';

/// Receives source/frame-aware messages from the custom native bridge.
///
/// Native code must obtain metadata from:
/// - iOS: `WKScriptMessage.frameInfo`
/// - Android: `WebViewCompat.WebMessageListener.onPostMessage(sourceOrigin, isMainFrame)`
///
/// Do not use this adapter with metadata parsed from `message.body`.
class SourceAwareMethodBridge {
  SourceAwareMethodBridge({
    required this.webViewId,
    required this.coordinator,
  }) : channel = MethodChannel('life_web_bridge/source_aware/$webViewId') {
    channel.setMethodCallHandler(_handleCall);
  }

  final String webViewId;
  final WebBridgeCoordinator coordinator;
  final MethodChannel channel;

  Future<Map<String, Object?>> _handleCall(MethodCall call) async {
    if (call.method != 'bridgeMessage') {
      throw MissingPluginException('Unknown bridge method ${call.method}');
    }

    final Map<Object?, Object?> arguments =
        Map<Object?, Object?>.from(call.arguments as Map<Object?, Object?>);
    final Map<Object?, Object?> source = Map<Object?, Object?>.from(
      (arguments['source'] as Map<Object?, Object?>?) ??
          const <Object?, Object?>{},
    );

    final String? originText = source['origin'] as String?;
    if (originText == null || originText.isEmpty) {
      return const BridgeResponse(
        requestId: null,
        ok: false,
        code: 'UNAUTHENTICATED',
        message: 'UNAUTHENTICATED',
      ).toJson();
    }

    final List<BridgeOrigin> ancestors =
        ((source['ancestors'] as List<Object?>?) ?? const <Object?>[])
            .map((Object? value) => BridgeOrigin.parse(value! as String))
            .toList();

    final TrustedFrameMetadata frame = TrustedFrameMetadata(
      origin: BridgeOrigin.parse(originText),
      isMainFrame: source['isMainFrame'] == true,
      platformFrameId: source['frameId'] as String?,
      ancestorChain: ancestors,
    );

    final BridgeResponse response = await coordinator.onMessage(
      IncomingTransportMessage(
        webViewId: webViewId,
        body: arguments['body'],
        frame: frame,
        replyToken: source['replyToken'] as String?,
      ),
    );
    return response.toJson();
  }
}
