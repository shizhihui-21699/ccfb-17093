/// Guard configuration. Every knob here trades compatibility for strictness,
/// and every default is the safe end of that trade.
library;

import 'attestation.dart';

/// Tuning for one bridge container.
final class BridgeConfig {
  const BridgeConfig({
    this.readyThreshold = ReadyStateThreshold.interactive,
    this.maxDelegationDepth = 1,
    this.enableSubframeGrants = false,
    this.attestationTimeout = const Duration(seconds: 2),
    this.requireVisibleDocument = true,
    this.maxGrantsPerContainer = 32,
    this.maxAttestationsPerMinute = 30,
    this.confirmationTimeout = const Duration(seconds: 30),
  });

  /// How far the document must be loaded before it may receive a grant.
  ///
  /// `interactive` is the compatibility default (shipped activity pages call
  /// native from `DOMContentLoaded`). Set `complete` when a page pulls in
  /// slow third-party scripts: it closes the pre-`load` injection window
  /// completely at the cost of those pages.
  final ReadyStateThreshold readyThreshold;

  /// Deepest descendant frame eligible for a grant. Depth 1 means only frames
  /// attested directly by the trusted top document. Each extra level
  /// delegates trust to an intermediate frame, so keep this at 1 unless the
  /// product genuinely nests activity content.
  final int maxDelegationDepth;

  /// Master switch for subframe grants. Off by default: an ad iframe is the
  /// threat model, and most activity pages need no subframe capability at
  /// all.
  final bool enableSubframeGrants;

  /// How long to wait for a platform main-frame evaluation before giving up.
  /// Exceeding it is treated as "not ready" (deny), never as "allow".
  final Duration attestationTimeout;

  /// Require `document.visibilityState == 'visible'` when granting. Blocks
  /// grants to backgrounded documents, which the user cannot see.
  final bool requireVisibleDocument;

  /// Cap on live grants per container; oldest are revoked first.
  final int maxGrantsPerContainer;

  /// Cap on native-initiated attestations per minute. The page cannot trigger
  /// attestation on its own except via `hello`, and `hello` is throttled here,
  /// so a hostile page cannot make us spin the evaluator.
  final int maxAttestationsPerMinute;

  /// How long a capability marked `requiresUserConfirmation` waits for the
  /// host's answer before it is denied.
  final Duration confirmationTimeout;

  BridgeConfig copyWith({
    ReadyStateThreshold? readyThreshold,
    int? maxDelegationDepth,
    bool? enableSubframeGrants,
    Duration? attestationTimeout,
    bool? requireVisibleDocument,
    int? maxGrantsPerContainer,
    int? maxAttestationsPerMinute,
    Duration? confirmationTimeout,
  }) => BridgeConfig(
    readyThreshold: readyThreshold ?? this.readyThreshold,
    maxDelegationDepth: maxDelegationDepth ?? this.maxDelegationDepth,
    enableSubframeGrants: enableSubframeGrants ?? this.enableSubframeGrants,
    attestationTimeout: attestationTimeout ?? this.attestationTimeout,
    requireVisibleDocument: requireVisibleDocument ?? this.requireVisibleDocument,
    maxGrantsPerContainer: maxGrantsPerContainer ?? this.maxGrantsPerContainer,
    maxAttestationsPerMinute: maxAttestationsPerMinute ?? this.maxAttestationsPerMinute,
    confirmationTimeout: confirmationTimeout ?? this.confirmationTimeout,
  );
}
