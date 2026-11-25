import 'response.dart';
import 'source.dart';

/// One message delivered by a native transport adapter.
///
/// [frame] must be null only for the legacy official JavaScriptChannel
/// fallback. Never populate it from JSON fields in the page.
class IncomingTransportMessage {
  const IncomingTransportMessage({
    required this.webViewId,
    required this.body,
    this.frame,
    this.replyToken,
  });

  final String webViewId;
  final Object? body;
  final TrustedFrameMetadata? frame;

  /// Platform reply handle, e.g. a JavaScriptReplyProxy identifier.
  final String? replyToken;
}

abstract class BridgeResponseSink {
  Future<void> send(
    BridgeResponse response, {
    required String webViewId,
    String? replyToken,
  });
}
