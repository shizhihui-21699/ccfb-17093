import 'origin.dart';

enum FrameKind {
  mainFrame,
  childFrame,
  unknown,
}

/// How the bridge learned the source identity.
///
/// [nativeFrameMetadata] is the only source that should unlock critical
/// capabilities when child-frame isolation matters. A JavaScript-supplied
/// `origin` or `isMainFrame` field is never represented here.
enum SourceAssurance {
  /// Supplied by iOS WKFrameInfo or Android WebMessageListener.
  nativeFrameMetadata(30),

  /// Possession of an unguessable ticket issued to a committed main frame.
  ///
  /// This blocks cross-origin child frames and naive early messages, but it
  /// cannot distinguish same-origin child frames or same-origin malicious
  /// scripts.
  documentTicket(20),

  /// No trustworthy source identity.
  untrusted(0);

  const SourceAssurance(this.rank);

  final int rank;

  bool atLeast(SourceAssurance required) => rank >= required.rank;
}

/// Trusted per-message metadata extracted outside the JavaScript world.
class TrustedFrameMetadata {
  const TrustedFrameMetadata({
    required this.origin,
    required this.isMainFrame,
    this.platformFrameId,
    this.ancestorChain = const <BridgeOrigin>[],
  });

  final BridgeOrigin origin;
  final bool isMainFrame;
  final String? platformFrameId;

  /// Top-to-immediate-parent origins when the native side can provide them.
  final List<BridgeOrigin> ancestorChain;

  FrameKind get frameKind =>
      isMainFrame ? FrameKind.mainFrame : FrameKind.childFrame;
}

/// A source after authentication. Handlers and policy may trust these fields.
class VerifiedSource {
  const VerifiedSource({
    required this.webViewId,
    required this.origin,
    required this.frameKind,
    required this.assurance,
    required this.documentId,
    this.ancestorChain = const <BridgeOrigin>[],
    this.platformFrameId,
  });

  final String webViewId;
  final BridgeOrigin origin;
  final FrameKind frameKind;
  final SourceAssurance assurance;
  final String? documentId;
  final String? platformFrameId;
  final List<BridgeOrigin> ancestorChain;

  bool get isMainFrame => frameKind == FrameKind.mainFrame;
  bool get isChildFrame => frameKind == FrameKind.childFrame;
}
