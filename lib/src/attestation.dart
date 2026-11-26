/// Parsing of the *native-initiated* main-frame read-back.
///
/// This is the only trustworthy source of document identity in the system.
/// The platform channel callback hands us a bare string: no URL, no frame, no
/// origin. Everything a page says about itself could have been said by an ad
/// frame, by a stale document, or by an injected script running early.
///
/// So we never ask the channel who is talking. Instead, the guard asks the
/// platform to evaluate a script **in the top-level frame only** and reads the
/// answer from the returned value (not from the channel). That evaluation:
///
/// * is issued by native, so no page script can spoof which document answered;
/// * reaches only the main frame, so an ad frame cannot answer on its behalf;
/// * reports `location.origin` as the *browser* computed it, not as the page
///   claimed;
/// * reports a per-document nonce planted at document start, which identifies
///   the document *instance*. A redirect produces a new document, hence a new
///   nonce, even when the URL looks unchanged.
///
/// Sub-frame identity is derived from the main frame's answer too: the
/// bootstrap in the main frame relays a native challenge to its descendants
/// with `postMessage`, and the *browser* fills in `event.origin` on the
/// replies. Native reads that list back in the same evaluation. A frame can
/// lie about its URL and its name; it cannot lie about `event.origin`.
library;

import 'dart:convert';

import 'message.dart';
import 'origin.dart';

/// Bounds for the read-back JSON. A page could stuff the read-back globals
/// with junk before native reads them; we cap size and shape.
const int kMaxAttestationBytes = 8192;
const int kMaxAckEntries = 64;

/// The result of a native-initiated main-frame evaluation.
final class DocumentAttestation {
  const DocumentAttestation({
    required this.nonce,
    required this.origin,
    required this.readyState,
    required this.visible,
    required this.challenge,
    required this.acks,
    required this.hasBootstrap,
  });

  /// Per-document random id planted at document start, before any page
  /// script runs. Identifies the document *instance*.
  final String nonce;

  /// `location.origin` as computed by the browser. `null` when the document
  /// has an opaque origin (about:blank, data:, sandboxed).
  final Origin? origin;

  /// `document.readyState`, one of `loading`/`interactive`/`complete`.
  final String readyState;

  /// `document.visibilityState == 'visible'`.
  final bool visible;

  /// The challenge this read-back was answering, echoed back by the script.
  final String challenge;

  /// Replies collected from descendant frames during this evaluation.
  final List<FrameAck> acks;

  /// False when the bootstrap script did not run in this document (e.g. the
  /// injection configuration is wrong, or the document replaced the globals).
  final bool hasBootstrap;

  /// Whether the document is far enough along for a grant. The threshold is
  /// configurable because the strictest setting (`complete`) costs
  /// compatibility with pages that call native during DOMContentLoaded.
  bool isReadyFor(ReadyStateThreshold threshold) =>
      switch (threshold) {
        ReadyStateThreshold.interactive =>
          readyState == 'interactive' || readyState == 'complete',
        ReadyStateThreshold.complete => readyState == 'complete',
      };

  /// Parses the raw return value of the main-frame evaluation.
  ///
  /// Throws [MessageFormatException]: a read-back we cannot parse is treated
  /// exactly like a hostile one, never like an absent one.
  static DocumentAttestation parse(Object? raw, {required String challenge}) {
    Object? decoded = raw;
    if (decoded is String) {
      if (decoded.length > kMaxAttestationBytes) {
        throw const MessageFormatException(DenyReason.tooLarge, 'attestation');
      }
      try {
        decoded = jsonDecode(decoded);
      } on FormatException {
        throw const MessageFormatException(DenyReason.malformed, 'attestation json');
      }
    }
    if (decoded is! Map<String, Object?>) {
      throw const MessageFormatException(DenyReason.malformed, 'attestation shape');
    }
    final Map<String, Object?> map = decoded;

    final Object? nonce = map['n'];
    if (nonce is! String || nonce.isEmpty || nonce.length > 96) {
      throw const MessageFormatException(DenyReason.malformed, 'attestation nonce');
    }

    final Object? echoed = map['c'];
    if (echoed is! String || echoed != challenge) {
      // The page answered a different question than we asked. Either a stale
      // evaluation raced a navigation, or the globals were replaced.
      throw const MessageFormatException(DenyReason.revokedToken, 'challenge');
    }

    final Object? originRaw = map['o'];
    final Origin? origin =
        originRaw is String ? Origin.tryParse(originRaw) : null;

    final Object? readyState = map['r'];
    if (readyState is! String ||
        (readyState != 'loading' &&
            readyState != 'interactive' &&
            readyState != 'complete')) {
      throw const MessageFormatException(DenyReason.malformed, 'readyState');
    }

    final Object? visible = map['v'];
    if (visible is! bool) {
      throw const MessageFormatException(DenyReason.malformed, 'visibility');
    }

    final Object? acksRaw = map['a'];
    if (acksRaw != null && acksRaw is! List) {
      throw const MessageFormatException(DenyReason.malformed, 'acks');
    }
    final List<FrameAck> acks = <FrameAck>[];
    for (final Object? entry in (acksRaw as List<Object?>?) ?? const <Object?>[]) {
      if (acks.length >= kMaxAckEntries) {
        throw const MessageFormatException(DenyReason.tooLarge, 'acks');
      }
      final FrameAck? ack = FrameAck.tryParse(entry);
      if (ack != null) acks.add(ack);
    }

    return DocumentAttestation(
      nonce: nonce,
      origin: origin,
      readyState: readyState,
      visible: visible,
      challenge: challenge,
      acks: acks,
      hasBootstrap: map['b'] == true,
    );
  }

  @override
  String toString() => 'DocumentAttestation(origin=$origin, readyState=$readyState, '
      'acks=${acks.length}, hasBootstrap=$hasBootstrap)';
}

/// One reply from a descendant frame, as attested by its parent.
final class FrameAck {
  const FrameAck({
    required this.nonce,
    required this.origin,
    required this.depth,
  });

  /// The replying frame's document nonce.
  final String nonce;

  /// The origin the **browser** attached to the reply (`event.origin`).
  /// Never the value the frame claims in its payload.
  final Origin? origin;

  /// Distance from the main frame. Depth 1 is directly attested by the
  /// trusted top-level frame; deeper depths are attested by an intermediate
  /// frame and are therefore only as trustworthy as that frame.
  final int depth;

  static FrameAck? tryParse(Object? raw) {
    if (raw is! Map<String, Object?>) return null;
    final Object? nonce = raw['n'];
    final Object? origin = raw['o'];
    final Object? depth = raw['d'];
    if (nonce is! String || nonce.isEmpty || nonce.length > 96) return null;
    if (depth is! int || depth < 1 || depth > 8) return null;
    return FrameAck(
      nonce: nonce,
      origin: origin is String ? Origin.tryParse(origin) : null,
      depth: depth,
    );
  }
}

/// How far a document must be loaded before a grant is issued.
enum ReadyStateThreshold {
  /// `DOMContentLoaded` has fired (`interactive`) or load finished.
  /// Compatibility default: shipped activity pages call native in
  /// `DOMContentLoaded` handlers.
  interactive,

  /// `load` has fired. Strictest; blocks every pre-load injection window,
  /// including those opened by slow third-party ad scripts.
  complete,
}
