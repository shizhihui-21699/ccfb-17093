/// Capability grants: the tokens that tie a channel message to a document.
///
/// A grant is created only after native has independently attested the
/// document (see `attestation.dart`). It carries:
///
/// * the origin and frame kind it was issued to,
/// * the set of capabilities that origin may use in that frame kind,
/// * a *generation* counter bumped on every navigation, which is how a token
///   from a previous page is invalidated before the new page's script can
///   possibly run,
/// * replay and rate-limit bookkeeping.
///
/// Tokens are unguessable random strings, but their security does **not**
/// depend on secrecy: even if a page leaks its own token, the token is bound
/// to one origin and one frame kind, and the platform evidence cross-check
/// rejects use from anywhere else.
library;

import 'dart:math';

import 'message.dart';
import 'origin.dart';

/// Token for a single document instance. Immutable.
final class CapabilityGrant {
  CapabilityGrant({
    required this.token,
    required this.origin,
    required this.frameKind,
    required this.capabilities,
    required this.generation,
    required this.documentNonce,
    required this.issuedAt,
    this.parentTopOrigin,
    this.revoked = false,
  });

  /// Opaque random token. 128 bits, base32-ish, no ambiguity.
  final String token;

  /// Attested origin of the document holding this grant.
  final Origin origin;

  /// Frame kind the grant was issued for. A subframe grant is additionally
  /// bound to [parentTopOrigin].
  final FrameKind frameKind;

  /// The capabilities this grant may reach. Always a subset of what the
  /// policy allows for `(origin, frameKind)`; re-checked per call regardless.
  final Set<String> capabilities;

  /// Monotonic per-container counter. Incremented by navigation; a grant with
  /// a generation older than the container's current one is dead.
  final int generation;

  /// Nonce of the document the grant was issued to. Used to bind the token
  /// to a document instance and to detect a stale token replayed after a
  /// navigation that returned to the same URL.
  final String documentNonce;

  /// Issuance time (injected clock; tests control it).
  final DateTime issuedAt;

  /// Set on revocation. Kept (not deleted) so we can distinguish "revoked"
  /// from "never existed" in logs without revealing anything to the caller.
  bool revoked;

  /// Per-minute call counter window. Opens lazily on the first call.
  DateTime? _windowStart;
  int _windowCount = 0;

  /// Request ids seen during this grant, bounded by [kMaxTrackedRequests].
  final Set<String> _seenRequestIds = <String>{};
  final List<String> _seenOrder = <String>[];

  /// Max request ids tracked per grant before dropping the oldest.
  static const int kMaxTrackedRequests = 256;

  /// True when the grant can still be used.
  bool get isActive => !revoked;

  /// Origin of the top-level document that hosted this grant. For a main
  /// frame grant this equals [origin]; for a subframe grant it is the parent
  /// page's origin, which is what the subframe was delegated *from*.
  final Origin? parentTopOrigin;

  /// Marks dead after a navigation. Idempotent.
  void revoke() {
    revoked = true;
  }

  /// Records a request id. Returns false when it is a replay.
  bool noteRequestId(String id) {
    if (!_seenRequestIds.add(id)) return false;
    _seenOrder.add(id);
    if (_seenOrder.length > kMaxTrackedRequests) {
      final String evicted = _seenOrder.removeAt(0);
      _seenRequestIds.remove(evicted);
    }
    return true;
  }

  /// Consumes one rate-limit slot. Returns false when over budget.
  bool consumeRateLimit(DateTime now, int maxCallsPerMinute) {
    final DateTime? start = _windowStart;
    if (start == null || now.difference(start) >= const Duration(minutes: 1)) {
      _windowStart = now;
      _windowCount = 0;
    }
    if (_windowCount >= maxCallsPerMinute) return false;
    _windowCount++;
    return true;
  }

  @override
  String toString() => 'CapabilityGrant(${origin.toString()}, ${frameKind.name}, '
      'gen=$generation, caps=${capabilities.length}, revoked=$revoked)';
}

/// Produces tokens and attestation nonces. Injectable so tests are
/// deterministic; production uses [SecureRandomGenerator].
abstract interface class TokenGenerator {
  /// A fresh channel token.
  String newToken();

  /// A fresh document nonce (planted in the page at document start).
  String newNonce();

  /// A fresh read-back challenge.
  String newChallenge();
}

/// Cryptographically random generator. 128 bits per value.
final class SecureRandomGenerator implements TokenGenerator {
  SecureRandomGenerator([Random? random])
      : _random = random ?? Random.secure();

  final Random _random;

  static const String _alphabet =
      'abcdefghijkmnpqrstuvwxyz23456789'; // no l, o, 0, 1

  @override
  String newToken() => _randomString(26);

  @override
  String newNonce() => _randomString(22);

  @override
  String newChallenge() => _randomString(26);

  String _randomString(int length) {
    final StringBuffer buffer = StringBuffer();
    for (int i = 0; i < length; i++) {
      buffer.write(_alphabet[_random.nextInt(_alphabet.length)]);
    }
    return buffer.toString();
  }
}

/// Counters and knock-out state for security events surfaced to the host.
enum SecurityEventKind {
  /// A message arrived with no token or a malformed envelope.
  malformed,

  /// A token was presented outside the container it was issued in, or the
  /// platform evidence disagreed with the token binding.
  tokenMisuse,

  /// A message arrived for a document whose grant was revoked by navigation.
  staleToken,

  /// The page claimed a different origin than the token's binding.
  originClaimMismatch,

  /// Handshake attempted before the document met the ready threshold.
  earlyHandshake,

  /// A capability was requested outside its frame scope (e.g. an ad iframe
  /// asking for the auth token).
  frameScopeViolation,

  /// A capability was requested that the origin has no rule for.
  capabilityViolation,

  /// A request id was replayed.
  replay,

  /// Rate limit exceeded.
  rateLimited,
}

/// A security event for the host's telemetry. Contains no PII and no token.
final class SecurityEvent {
  const SecurityEvent({
    required this.kind,
    required this.at,
    this.origin,
    this.frameKind,
    this.capability,
    this.reason,
  });

  final SecurityEventKind kind;
  final DateTime at;

  /// Attested origin, when known. `null` when the message could not be
  /// attributed (which is itself the interesting signal).
  final Origin? origin;

  final FrameKind? frameKind;
  final String? capability;
  final DenyReason? reason;

  @override
  String toString() => 'SecurityEvent(${kind.name}, origin=$origin, '
      'frame=$frameKind, cap=$capability, reason=$reason)';
}
