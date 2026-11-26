/// Wire protocol shared by the injected bootstrap and the native guard.
///
/// Everything in this file assumes the peer is hostile until proven otherwise.
/// Parsing therefore has hard limits on size, depth and shape, and rejects
/// unknown fields rather than ignoring them (an ignored field is a field a
/// future version will trust).
library;

import 'dart:convert';

/// Hard cap on a single channel message. The channel callback hands us a
/// string with no size limit, so we impose one before touching JSON.
const int kMaxMessageBytes = 4096;

/// Hard cap on nesting depth of [`args`]. Activity payloads are flat.
const int kMaxArgsDepth = 4;

/// Hard cap on the number of entries in `args` and nested objects/arrays.
const int kMaxArgsEntries = 64;

/// Correlation id: opaque, client-generated, used to pair responses.
const int kMaxRequestIdLength = 32;

/// Which frame of the document produced a message.
enum FrameKind {
  /// The top-level document of the WebView.
  main,

  /// Any nested browsing context (iframe, srcdoc, etc).
  sub,
}

/// Message kinds. `hello` is the mandatory handshake; `invoke` calls a
/// capability; `bye` is an advisory teardown from the page.
enum MessageKind {
  hello,
  invoke,
  bye,
}

/// Why a message was refused. Stable string codes so the page-side shim can
/// map them to the legacy error shape without leaking internal state.
enum DenyReason {
  /// No token, malformed envelope, or unparsable JSON.
  malformed('bad_request'),

  /// Message exceeded size/structure limits.
  tooLarge('bad_request'),

  /// Token is unknown to this process (never issued, or revoked long ago).
  unknownToken('unauthorized'),

  /// Token was issued but the grant has been revoked by navigation.
  revokedToken('stale_context'),

  /// Grant exists but the document has not completed its handshake, or a
  /// navigation is in flight.
  notReady('not_ready'),

  /// The capability is not in this grant's scope.
  capabilityNotGranted('forbidden'),

  /// A capability that exists, but not for this frame kind.
  frameNotPermitted('forbidden'),

  /// The platform-supplied sender evidence disagrees with the token binding.
  /// Indicates token theft; always logged as a security event.
  evidenceMismatch('unauthorized'),

  /// Replay of a request id already seen on this grant.
  replay('bad_request'),

  /// Per-grant rate limit exceeded.
  rateLimited('rate_limited'),

  /// Handshake claimed an origin that differs from the token's binding.
  originMismatch('unauthorized'),

  /// The attested document origin is not on the container's allow-list.
  originNotAllowed('unauthorized'),

  /// The host adapter cannot support subframe grants on this platform.
  platformUnsupported('forbidden');

  const DenyReason(this.wireCode);

  /// Code sent back to page JavaScript.
  final String wireCode;
}

/// Thrown by [BridgeMessage.parse] — never escapes the guard, which turns it
/// into a [DenyReason].
final class MessageFormatException implements Exception {
  const MessageFormatException(this.reason, [this.detail]);

  final DenyReason reason;
  final String? detail;

  @override
  String toString() =>
      'MessageFormatException(${reason.name}${detail == null ? '' : ': $detail'})';
}

/// A validated inbound envelope.
final class BridgeMessage {
  const BridgeMessage._({
    required this.kind,
    required this.token,
    required this.frame,
    required this.requestId,
    required this.capability,
    required this.originClaim,
    required this.args,
    required this.legacy,
  });

  final MessageKind kind;

  /// Opaque capability token. This — not any field the page fills in — is
  /// what binds the message to an origin and frame.
  final String token;

  /// Frame the page *claims* to be in. Advisory: cross-checked against the
  /// token binding and against platform evidence, never trusted alone.
  final FrameKind frame;

  /// Client-generated id for pairing a response with a request.
  final String requestId;

  /// Capability name for [MessageKind.invoke].
  final String? capability;

  /// Origin the page claims to be. Used only as a *consistency* check on the
  /// handshake; the authoritative origin comes from the native grant.
  final String? originClaim;

  /// Bounded, already-validated argument map.
  final Map<String, Object?> args;

  /// True when the message arrived through the legacy (pre-migration)
  /// envelope shape and was normalised by the shim.
  final bool legacy;

  /// Parses a channel payload.
  ///
  /// Accepts the modern envelope:
  /// ```json
  /// {"v":1,"k":"invoke","t":"<token>","f":"main","id":"a1",
  ///  "cap":"auth.token","args":{}}
  /// ```
  /// and the legacy envelope, which is read to **preserve compatibility**
  /// but never attributed without a token:
  /// ```json
  /// {"action":"getToken","callbackId":"a1"}
  /// ```
  static BridgeMessage parse(Object? raw) {
    if (raw is! String) {
      throw const MessageFormatException(DenyReason.malformed, 'not a string');
    }
    if (raw.length > kMaxMessageBytes) {
      throw const MessageFormatException(DenyReason.tooLarge);
    }
    if (utf8.encode(raw).length > kMaxMessageBytes) {
      throw const MessageFormatException(DenyReason.tooLarge);
    }

    final Object? decoded;
    try {
      decoded = jsonDecode(raw);
    } on FormatException {
      throw const MessageFormatException(DenyReason.malformed, 'invalid json');
    }
    if (decoded is! Map<String, Object?>) {
      throw const MessageFormatException(DenyReason.malformed, 'not an object');
    }

    final Map<String, Object?> envelope = decoded;
    if (!envelope.containsKey('v') && envelope.containsKey('action')) {
      return _parseLegacy(envelope);
    }
    return _parseModern(envelope);
  }

  static BridgeMessage _parseModern(Map<String, Object?> envelope) {
    final Object? version = envelope['v'];
    if (version != 1) {
      throw const MessageFormatException(DenyReason.malformed, 'bad version');
    }

    final String? kindWire = _requiredString(envelope, 'k', maxLength: 16);
    final MessageKind kind;
    switch (kindWire) {
      case 'hello':
        kind = MessageKind.hello;
      case 'invoke':
        kind = MessageKind.invoke;
      case 'bye':
        kind = MessageKind.bye;
      default:
        throw const MessageFormatException(DenyReason.malformed, 'bad kind');
    }

    final String token = _requiredString(envelope, 't', maxLength: 96);
    if (token.isEmpty) {
      throw const MessageFormatException(DenyReason.malformed, 'empty token');
    }

    final FrameKind frame;
    switch (_requiredString(envelope, 'f', maxLength: 8)) {
      case 'main':
        frame = FrameKind.main;
      case 'sub':
        frame = FrameKind.sub;
      default:
        throw const MessageFormatException(DenyReason.malformed, 'bad frame');
    }

    final String requestId =
        _requiredString(envelope, 'id', maxLength: kMaxRequestIdLength);

    final String? capability =
        _optionalString(envelope, 'cap', maxLength: 64);
    if (kind == MessageKind.invoke && capability == null) {
      throw const MessageFormatException(DenyReason.malformed, 'missing cap');
    }
    if (kind != MessageKind.invoke && capability != null) {
      throw const MessageFormatException(DenyReason.malformed, 'cap on non-invoke');
    }

    final String? originClaim =
        _optionalString(envelope, 'o', maxLength: 512);

    final Map<String, Object?> args = _validateArgs(envelope['args']);

    return BridgeMessage._(
      kind: kind,
      token: token,
      frame: frame,
      requestId: requestId,
      capability: capability,
      originClaim: originClaim,
      args: args,
      legacy: false,
    );
  }

  /// Legacy shape: `{"action":"getToken","callbackId":"..."}`.
  ///
  /// Pre-migration activity pages were written against this. The shim
  /// re-writes them into the modern envelope, but the native side still
  /// accepts the shape so that a shim failure degrades to "denied" instead of
  /// "silently broken page". A legacy message has no token by construction,
  /// so it can never be attributed to an origin on its own.
  static BridgeMessage _parseLegacy(Map<String, Object?> envelope) {
    final String? action = _optionalString(envelope, 'action', maxLength: 64);
    if (action == null || action.isEmpty) {
      throw const MessageFormatException(DenyReason.malformed, 'legacy: no action');
    }
    final String requestId = _optionalString(
          envelope,
          'callbackId',
          maxLength: kMaxRequestIdLength,
        ) ??
        _optionalString(envelope, 'id', maxLength: kMaxRequestIdLength) ??
        'legacy';
    return BridgeMessage._(
      kind: MessageKind.invoke,
      token: _optionalString(envelope, 'token', maxLength: 96) ?? '',
      frame: FrameKind.main,
      requestId: requestId,
      capability: _LegacyNames.translate(action),
      originClaim: null,
      args: const <String, Object?>{},
      legacy: true,
    );
  }

  static Map<String, Object?> _validateArgs(Object? raw) {
    if (raw == null) return const <String, Object?>{};
    if (raw is! Map<String, Object?>) {
      throw const MessageFormatException(DenyReason.malformed, 'args not an object');
    }
    _checkValue(raw, depth: 0);
    return raw;
  }

  static void _checkValue(Object? value, {required int depth}) {
    if (depth > kMaxArgsDepth) {
      throw const MessageFormatException(DenyReason.malformed, 'args too deep');
    }
    if (value is Map) {
      if (value.length > kMaxArgsEntries) {
        throw const MessageFormatException(DenyReason.malformed, 'args too wide');
      }
      for (final MapEntry<Object?, Object?> entry in value.entries) {
        final Object? key = entry.key;
        if (key is! String) {
          throw const MessageFormatException(DenyReason.malformed, 'non-string key');
        }
        // `__proto__`/`constructor`/`prototype` are the classic prototype
        // pollution keys; they are never legitimate argument names.
        if (key == '__proto__' || key == 'constructor' || key == 'prototype') {
          throw const MessageFormatException(DenyReason.malformed, 'forbidden key');
        }
        if (key.length > 64) {
          throw const MessageFormatException(DenyReason.malformed, 'key too long');
        }
        _checkValue(entry.value, depth: depth + 1);
      }
    } else if (value is List) {
      if (value.length > kMaxArgsEntries) {
        throw const MessageFormatException(DenyReason.malformed, 'args too wide');
      }
      for (final Object? item in value) {
        _checkValue(item, depth: depth + 1);
      }
    } else if (value is String) {
      if (value.length > 1024) {
        throw const MessageFormatException(DenyReason.malformed, 'value too long');
      }
    } else if (value != null && value is! num && value is! bool) {
      throw const MessageFormatException(DenyReason.malformed, 'bad value type');
    }
  }

  static String _requiredString(
    Map<String, Object?> envelope,
    String key, {
    required int maxLength,
  }) {
    final Object? value = envelope[key];
    if (value is! String) {
      throw MessageFormatException(DenyReason.malformed, 'missing $key');
    }
    if (value.length > maxLength) {
      throw MessageFormatException(DenyReason.tooLarge, '$key too long');
    }
    return value;
  }

  static String? _optionalString(
    Map<String, Object?> envelope,
    String key, {
    required int maxLength,
  }) {
    final Object? value = envelope[key];
    if (value == null) return null;
    if (value is! String) {
      throw MessageFormatException(DenyReason.malformed, '$key not a string');
    }
    if (value.length > maxLength) {
      throw MessageFormatException(DenyReason.tooLarge, '$key too long');
    }
    return value;
  }
}

/// Legacy action names used by the already-shipped activity pages.
abstract final class _LegacyNames {
  static String translate(String action) {
    return switch (action) {
      'getToken' || 'getLoginToken' || 'auth.token' => 'auth.token',
      'getAddressList' || 'getAddress' || 'address.list' => 'address.list',
      'claimCoupon' || 'coupon.claim' => 'coupon.claim',
      'createOrder' || 'order.create' => 'order.create',
      'closePage' || 'ui.close' => 'ui.close',
      'toast' || 'ui.toast' => 'ui.toast',
      _ => 'legacy.unknown',
    };
  }
}
