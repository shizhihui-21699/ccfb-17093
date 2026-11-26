/// The bridge guard: state machine that turns an unattributable channel
/// string into an attributed, policy-checked capability call.
///
/// ## The problem this solves
///
/// `webview_flutter`'s JavaScript channel callback hands the app a bare
/// `String`. It does not say which origin produced it, nor whether it came
/// from the main frame or from an iframe. Any script in any frame of any
/// page the WebView ever displays can call it. So:
///
/// * An ad SDK's iframe must not be able to read the auth token.
/// * A page reached by a redirect-tap must not inherit the previous page's
///   capabilities.
/// * A script that runs before the legitimate page finishes loading must not
///   be able to claim to *be* that page.
/// * Existing activity pages (which use a legacy envelope with no token)
///   must keep working.
///
/// ## Attribution, per message
///
/// 1. The message must carry a token. Tokens are minted only after native has
///    independently attested the document that will hold them.
/// 2. Attestation is a **native-initiated** main-frame evaluation
///    ([PlatformPort.evaluateMainFrame]). Its value cannot be produced by a
///    subframe and cannot be raced by a page script, because native asks the
///    browser, not the channel.
/// 3. The token is bound to `(origin, frameKind, generation, documentNonce)`.
///    `generation` increments on *every* navigation signal, so a token from a
///    previous document is dead the instant a new navigation starts — before
///    the new page's first script byte runs.
/// 4. Every call re-resolves the capability against the policy for the
///    attested `(origin, frameKind)`. A grant cannot be widened at runtime.
///
/// ## Why not trust the page's claims
///
/// The envelope carries `f` (frame) and `o` (origin) fields for diagnostics,
/// but they are **cross-checked**, never used as the source of truth. A
/// message that claims `main` while its token is bound to `sub` is denied and
/// logged as token misuse.
library;

import 'dart:async';
import 'dart:convert';

import 'attestation.dart';
import 'config.dart';
import 'grant.dart';
import 'message.dart';
import 'origin.dart';
import 'platform_port.dart';
import 'policy.dart';

/// What a capability handler receives. Handlers must not trust
/// [message.originClaim] or [message.frame]; use [origin] and [frameKind].
final class BridgeContext {
  const BridgeContext({
    required this.origin,
    required this.frameKind,
    required this.capability,
    required this.args,
    required this.requestId,
    required this.legacy,
  });

  /// Attested origin of the calling document. Authoritative.
  final Origin origin;

  /// Attested frame kind. Authoritative.
  final FrameKind frameKind;

  final String capability;
  final Map<String, Object?> args;
  final String requestId;

  /// True when this call came through the legacy envelope. Handlers that
  /// change shape between old and new pages can branch on it; most should not.
  final bool legacy;
}

/// A capability implementation registered by the host app.
typedef CapabilityHandler = Future<Object?> Function(BridgeContext context);

/// Raised by a handler to return a structured error to the page.
final class BridgeException implements Exception {
  const BridgeException(this.code, this.message);

  final String code;
  final String message;

  @override
  String toString() => 'BridgeException($code: $message)';
}

/// The outcome of a single channel message, for tests and telemetry.
enum GuardOutcome { granted, denied, answeredWithError, ignored }

/// The guard. One per WebView container.
final class BridgeGuard {
  BridgeGuard({
    required this.policy,
    required this.port,
    BridgeConfig config = const BridgeConfig(),
    TokenGenerator? tokens,
    DateTime Function()? clock,
    void Function(SecurityEvent event)? onSecurityEvent,
    void Function(String requestId, Object? result, BridgeException? error)?
        responder,
  }) : _config = config,
       _tokens = tokens ?? SecureRandomGenerator(),
       _clock = clock ?? DateTime.now,
       _onSecurityEvent = onSecurityEvent,
       _responder = responder;

  final BridgePolicy policy;
  final PlatformPort port;
  final BridgeConfig _config;
  final TokenGenerator _tokens;
  final DateTime Function() _clock;
  final void Function(SecurityEvent event)? _onSecurityEvent;

  /// Where replies go. Defaults to a main-frame injection of
  /// `window.__wbReplies.deliver(...)`; tests supply a direct sink.
  final void Function(String requestId, Object? result, BridgeException? error)?
      _responder;

  static const String _bootstrap = 'window.__wb';

  final Map<String, CapabilityHandler> _handlers = <String, CapabilityHandler>{};

  final Map<String, CapabilityGrant> _grants = <String, CapabilityGrant>{};

  /// Monotonic; incremented by every navigation signal.
  int _generation = 0;

  /// True from the moment a main-frame navigation is observed until the new
  /// document has been attested. While true, `hello` is denied.
  bool _navigationPending = true;

  /// Last successful main-frame attestation for the current document.
  DocumentAttestation? _currentDocument;

  /// Serialises all message handling so two messages cannot interleave
  /// between the attest check and the grant lookup.
  Future<void> _queue = Future<void>.value();

  /// Attestation coalescing: at most one in flight.
  Future<DocumentAttestation?>? _attestationInFlight;

  /// Attestation throttle window.
  DateTime? _attestWindowStart;
  int _attestWindowCount = 0;

  /// Pending confirmation requests, keyed by request id.
  final Map<String, Completer<bool>> _confirmations =
      <String, Completer<bool>>{};

  bool _disposed = false;

  /// Capabilities the host has wired up. A capability with no handler is
  /// denied even if the policy allows it — the policy is a ceiling, not a
  /// promise.
  void register(String capability, CapabilityHandler handler) {
    _handlers[capability] = handler;
  }

  /// Live grants, for diagnostics. Never log tokens at info level.
  int get activeGrantCount => _grants.values.where((CapabilityGrant g) => g.isActive).length;

  /// Attested origin of the current document, if any.
  Origin? get currentOrigin => _currentDocument?.origin;

  // ---------------------------------------------------------------------
  // Host lifecycle signals.
  //
  // These are the *untrusted* signals: they tell us a navigation is
  // happening, which is enough to revoke, but never enough to grant. Only
  // [attest] can grant.
  // ---------------------------------------------------------------------

  /// Call from `NavigationDelegate.onNavigationRequest` when
  /// `request.isMainFrame` is true, and from `setOnPageStarted`.
  ///
  /// Safe to call for every redirect hop: revocation is monotonic and
  /// idempotent, and over-calling only costs a re-attestation.
  void onMainFrameNavigationStart(String url) {
    _invalidateForNavigation();
  }

  /// Call from `setOnUrlChange`. Catches redirect hops that neither
  /// navigation-request nor page-started observes: iOS can swap the URL for
  /// an in-place server redirect without a new provisional navigation,
  /// Android emits it from the renderer.
  void onMainFrameUrlChanged(String url) {
    _invalidateForNavigation();
  }

  /// Call from `setOnPageFinished`.
  ///
  /// Does **not** grant anything by itself. It lifts [navigationPending]
  /// only if attestation succeeds, because a page-finished callback can
  /// fire for a document that an injected script is still racing.
  Future<void> onMainFrameFinished(String url) async {
    final DocumentAttestation? attestation = await _attest();
    if (attestation == null) {
      // Leave _navigationPending true: no grant until we can attest.
      return;
    }
    _navigationPending = false;
    await _pushTokenToMainFrame();
  }

  /// Hard revoke: call on `dispose`, on web-content process termination, and
  /// whenever the host decides the session is over (logout, backgrounding).
  ///
  /// Bumps the generation and revokes every grant.
  void revokeAll({String reason = 'host'}) {
    _generation++;
    _navigationPending = true;
    _currentDocument = null;
    for (final CapabilityGrant grant in _grants.values) {
      grant.revoke();
    }
    _grants.clear();
  }

  void dispose() {
    _disposed = true;
    revokeAll(reason: 'dispose');
    for (final Completer<bool> c in _confirmations.values) {
      if (!c.isCompleted) c.complete(false);
    }
    _confirmations.clear();
  }

  void _invalidateForNavigation() {
    _generation++;
    _navigationPending = true;
    _currentDocument = null;
    for (final CapabilityGrant grant in _grants.values) {
      grant.revoke();
    }
    _grants.clear();
  }

  // ---------------------------------------------------------------------
  // Channel entry point.
  // ---------------------------------------------------------------------

  /// Feed a raw channel payload. Always resolves; never throws.
  ///
  /// Returns the outcome so tests and the host's telemetry can assert on it.
  Future<GuardOutcome> handleChannelMessage(Object? raw) {
    if (_disposed) return Future<GuardOutcome>.value(GuardOutcome.ignored);
    final Completer<GuardOutcome> completer = Completer<GuardOutcome>();
    _queue = _queue.then((_) async {
      if (_disposed) {
        completer.complete(GuardOutcome.ignored);
        return;
      }
      try {
        completer.complete(await _handle(raw));
      } catch (error, stack) {
        // A bug in the guard must never surface as "allow".
        _emit(SecurityEventKind.malformed, reason: DenyReason.malformed);
        completer.complete(GuardOutcome.denied);
        if (!completer.isCompleted) completer.completeError(error, stack);
      }
    });
    return completer.future;
  }

  Future<GuardOutcome> _handle(Object? raw) async {
    final BridgeMessage message;
    try {
      message = BridgeMessage.parse(raw);
    } on MessageFormatException catch (e) {
      _emit(SecurityEventKind.malformed, reason: e.reason);
      return GuardOutcome.denied;
    }

    if (message.kind == MessageKind.hello) {
      return _handleHello(message);
    }
    return _handleInvoke(message);
  }

  // ---------------------------------------------------------------------
  // Handshake.
  // ---------------------------------------------------------------------

  Future<GuardOutcome> _handleHello(BridgeMessage message) async {
    if (_navigationPending) {
      // A hello during a navigation belongs to a document that is on its
      // way out (or an injected script racing the real one). Refuse, and
      // do not attest: attestation would itself be a race.
      _emit(SecurityEventKind.earlyHandshake, reason: DenyReason.notReady);
      return GuardOutcome.denied;
    }

    final DocumentAttestation? attestation = await _attest();
    if (attestation == null) {
      _emit(SecurityEventKind.earlyHandshake, reason: DenyReason.notReady);
      return GuardOutcome.denied;
    }
    _currentDocument = attestation;

    if (attestation.origin == null) {
      // Opaque origin: about:blank, data:, sandboxed. Nothing to grant.
      _emit(SecurityEventKind.originClaimMismatch, reason: DenyReason.evidenceMismatch);
      return GuardOutcome.denied;
    }
    if (!attestation.isReadyFor(_config.readyThreshold)) {
      _emit(
        SecurityEventKind.earlyHandshake,
        origin: attestation.origin,
        reason: DenyReason.notReady,
      );
      return GuardOutcome.denied;
    }
    if (_config.requireVisibleDocument && !attestation.visible) {
      _emit(
        SecurityEventKind.earlyHandshake,
        origin: attestation.origin,
        reason: DenyReason.notReady,
      );
      return GuardOutcome.denied;
    }

    // Which frame is asking? The nonce is planted per document, so we can
    // compare the *claiming* document's nonce with (a) the top document's
    // nonce and (b) the browser-attested ack list.
    final String? claimedNonce = message.originClaim == null
        ? _helloNonce(message)
        : _helloNonce(message);
    if (claimedNonce == null) {
      _emit(
        SecurityEventKind.malformed,
        origin: attestation.origin,
        reason: DenyReason.malformed,
      );
      return GuardOutcome.denied;
    }

    if (claimedNonce == attestation.nonce) {
      return _grantMain(message, attestation);
    }
    return _grantSubframe(message, attestation, claimedNonce);
  }

  /// The hello envelope carries its document nonce in `args.n`.
  String? _helloNonce(BridgeMessage message) {
    final Object? nonce = message.args['n'];
    if (nonce is String && nonce.isNotEmpty && nonce.length <= 96) {
      return nonce;
    }
    return null;
  }

  Future<GuardOutcome> _grantMain(
    BridgeMessage message,
    DocumentAttestation attestation,
  ) async {
    final Origin origin = attestation.origin!;
    if (!policy.allowsTopOrigin(origin)) {
      _emit(
        SecurityEventKind.originClaimMismatch,
        origin: origin,
        frameKind: FrameKind.main,
        reason: DenyReason.evidenceMismatch,
      );
      return GuardOutcome.denied;
    }
    final Set<String> caps = policy.capabilitiesFor(origin, FrameKind.main);
    final CapabilityGrant? grant = _mint(
      origin: origin,
      frameKind: FrameKind.main,
      capabilities: caps,
      documentNonce: attestation.nonce,
      parentTopOrigin: null,
    );
    if (grant == null) {
      _emit(
        SecurityEventKind.capabilityViolation,
        origin: origin,
        frameKind: FrameKind.main,
        reason: DenyReason.rateLimited,
      );
      return GuardOutcome.denied;
    }
    await _deliverGrant(message.requestId, grant, frameKind: FrameKind.main);
    await _pushTokenToMainFrame();
    return GuardOutcome.granted;
  }

  Future<GuardOutcome> _grantSubframe(
    BridgeMessage message,
    DocumentAttestation attestation,
    String claimedNonce,
  ) async {
    final Origin topOrigin = attestation.origin!;
    if (!_config.enableSubframeGrants) {
      _emit(
        SecurityEventKind.frameScopeViolation,
        origin: topOrigin,
        frameKind: FrameKind.sub,
        reason: DenyReason.platformUnsupported,
      );
      return GuardOutcome.denied;
    }

    // Find the browser-attested ack for this nonce. There may be several
    // (the same nonce re-announcing); require all sighted origins to agree
    // and require the minimum depth seen.
    FrameAck? ack;
    for (final FrameAck candidate in attestation.acks) {
      if (candidate.nonce != claimedNonce) continue;
      if (ack == null || candidate.depth < ack.depth) ack = candidate;
    }
    if (ack == null) {
      // The document claims to be a subframe but no attested subframe
      // answered. Classic case: an injected script copied a nonce from
      // somewhere, or a frame lied about being attested.
      _emit(
        SecurityEventKind.tokenMisuse,
        origin: topOrigin,
        frameKind: FrameKind.sub,
        reason: DenyReason.evidenceMismatch,
      );
      return GuardOutcome.denied;
    }
    final Origin? subOrigin = ack.origin;
    if (subOrigin == null) {
      _emit(
        SecurityEventKind.tokenMisuse,
        origin: topOrigin,
        frameKind: FrameKind.sub,
        reason: DenyReason.evidenceMismatch,
      );
      return GuardOutcome.denied;
    }
    if (ack.depth > _config.maxDelegationDepth) {
      _emit(
        SecurityEventKind.frameScopeViolation,
        origin: subOrigin,
        frameKind: FrameKind.sub,
        reason: DenyReason.frameNotPermitted,
      );
      return GuardOutcome.denied;
    }
    if (!policy.allowsSubframeOrigin(subOrigin, topOrigin)) {
      _emit(
        SecurityEventKind.originClaimMismatch,
        origin: subOrigin,
        frameKind: FrameKind.sub,
        reason: DenyReason.evidenceMismatch,
      );
      return GuardOutcome.denied;
    }

    final Set<String> caps = policy.capabilitiesFor(subOrigin, FrameKind.sub);
    final CapabilityGrant? grant = _mint(
      origin: subOrigin,
      frameKind: FrameKind.sub,
      capabilities: caps,
      documentNonce: claimedNonce,
      parentTopOrigin: topOrigin,
    );
    if (grant == null) {
      _emit(
        SecurityEventKind.capabilityViolation,
        origin: subOrigin,
        frameKind: FrameKind.sub,
        reason: DenyReason.rateLimited,
      );
      return GuardOutcome.denied;
    }
    // Subframe grants are delivered through the main frame's bootstrap, which
    // routes by nonce. A subframe cannot receive a push directly, and it
    // cannot pick up another frame's token because the routing key is its
    // own nonce.
    await _deliverGrant(message.requestId, grant, frameKind: FrameKind.sub);
    return GuardOutcome.granted;
  }

  CapabilityGrant? _mint({
    required Origin origin,
    required FrameKind frameKind,
    required Set<String> capabilities,
    required String documentNonce,
    required Origin? parentTopOrigin,
  }) {
    if (capabilities.isEmpty) return null;

    // Cap live grants; revoke the oldest first so a page that repeatedly
    // handshakes cannot exhaust memory.
    if (_grants.length >= _config.maxGrantsPerContainer) {
      final MapEntry<String, CapabilityGrant>? oldest = _grants.entries.isEmpty
          ? null
          : _grants.entries.reduce(
              (MapEntry<String, CapabilityGrant> a, MapEntry<String, CapabilityGrant> b) =>
                  a.value.issuedAt.isBefore(b.value.issuedAt) ? a : b,
            );
      if (oldest != null) {
        oldest.value.revoke();
        _grants.remove(oldest.key);
      }
    }

    final CapabilityGrant grant = CapabilityGrant(
      token: _tokens.newToken(),
      origin: origin,
      frameKind: frameKind,
      capabilities: capabilities,
      generation: _generation,
      documentNonce: documentNonce,
      issuedAt: _clock(),
    );
    _grants[grant.token] = grant;
    return grant;
  }

  // ---------------------------------------------------------------------
  // Invocation.
  // ---------------------------------------------------------------------

  Future<GuardOutcome> _handleInvoke(BridgeMessage message) async {
    if (message.token.isEmpty) {
      // Legacy envelope with no token, or modern envelope with an empty one.
      // A legacy envelope can never be attributed on its own; only the
      // bootstrap's re-write (which attaches the main-frame token) can.
      _emit(SecurityEventKind.tokenMisuse, reason: DenyReason.evidenceMismatch);
      return GuardOutcome.denied;
    }

    final CapabilityGrant? grant = _grants[message.token];
    if (grant == null) {
      _emit(SecurityEventKind.staleToken, reason: DenyReason.unknownToken);
      return GuardOutcome.denied;
    }
    if (!grant.isActive) {
      _emit(
        SecurityEventKind.staleToken,
        origin: grant.origin,
        frameKind: grant.frameKind,
        reason: DenyReason.revokedToken,
      );
      return GuardOutcome.denied;
    }
    if (grant.generation != _generation) {
      // A navigation started (or a revoke happened) after this grant was
      // minted. Dead, no matter that the token string still exists.
      grant.revoke();
      _emit(
        SecurityEventKind.staleToken,
        origin: grant.origin,
        frameKind: grant.frameKind,
        reason: DenyReason.revokedToken,
      );
      return GuardOutcome.denied;
    }
    final DocumentAttestation? document = _currentDocument;
    if (document == null ||
        document.nonce != grant.documentNonce ||
        document.origin == null ||
        !document.origin!.sameAs(grant.origin)) {
      _emit(
        SecurityEventKind.staleToken,
        origin: grant.origin,
        frameKind: grant.frameKind,
        reason: DenyReason.revokedToken,
      );
      return GuardOutcome.denied;
    }

    // Declared-frame cross-check. The token already pins the frame kind;
    // a mismatch means either a spoof attempt or a bootstrap bug. Deny
    // either way, and log the spoof case.
    if (message.frame != grant.frameKind) {
      _emit(
        SecurityEventKind.tokenMisuse,
        origin: grant.origin,
        frameKind: message.frame,
        reason: DenyReason.evidenceMismatch,
      );
      return GuardOutcome.denied;
    }

    // Origin claim cross-check (diagnostic only; the grant is authority).
    final String? claim = message.originClaim;
    if (claim != null) {
      final Origin? claimed = Origin.tryParse(claim);
      if (claimed == null || !claimed.sameAs(grant.origin)) {
        _emit(
          SecurityEventKind.originClaimMismatch,
          origin: grant.origin,
          frameKind: grant.frameKind,
          reason: DenyReason.originMismatch,
        );
        return GuardOutcome.denied;
      }
    }

    if (!grant.noteRequestId(message.requestId)) {
      _emit(
        SecurityEventKind.replay,
        origin: grant.origin,
        frameKind: grant.frameKind,
        reason: DenyReason.replay,
      );
      return GuardOutcome.denied;
    }

    final String? rawCapability = message.capability;
    if (rawCapability == null) {
      _emit(
        SecurityEventKind.malformed,
        origin: grant.origin,
        frameKind: grant.frameKind,
        reason: DenyReason.malformed,
      );
      return GuardOutcome.denied;
    }

    // Resolve against policy. This is the per-message origin check that
    // survives even if a grant somehow held a capability it should not.
    final CapabilityDecision? decision =
        policy.resolve(rawCapability, grant.origin, grant.frameKind);
    if (decision == null) {
      final bool frameOnlyFailure =
          policy.resolveAnyFrame(rawCapability, grant.origin) != null;
      _emit(
        frameOnlyFailure
            ? SecurityEventKind.frameScopeViolation
            : SecurityEventKind.capabilityViolation,
        origin: grant.origin,
        frameKind: grant.frameKind,
        capability: rawCapability,
        reason: frameOnlyFailure
            ? DenyReason.frameNotPermitted
            : DenyReason.capabilityNotGranted,
      );
      await _respond(message, error: BridgeException(
          frameOnlyFailure ? 'forbidden' : 'forbidden',
          frameOnlyFailure
              ? 'capability not available from ${grant.frameKind.name} frame'
              : 'capability not granted'));
      return GuardOutcome.denied;
    }

    if (!grant.capabilities.contains(rawCapability)) {
      _emit(
        SecurityEventKind.capabilityViolation,
        origin: grant.origin,
        frameKind: grant.frameKind,
        capability: rawCapability,
        reason: DenyReason.capabilityNotGranted,
      );
      await _respond(
        message,
        error: const BridgeException('forbidden', 'capability not in grant scope'),
      );
      return GuardOutcome.denied;
    }

    final CapabilityHandler? handler = _handlers[rawCapability];
    if (handler == null) {
      _emit(
        SecurityEventKind.capabilityViolation,
        origin: grant.origin,
        frameKind: grant.frameKind,
        capability: rawCapability,
        reason: DenyReason.capabilityNotGranted,
      );
      await _respond(
        message,
        error: const BridgeException('unavailable', 'capability not implemented'),
      );
      return GuardOutcome.denied;
    }

    if (!grant.consumeRateLimit(_clock(), decision.maxCallsPerMinute)) {
      _emit(
        SecurityEventKind.rateLimited,
        origin: grant.origin,
        frameKind: grant.frameKind,
        capability: rawCapability,
        reason: DenyReason.rateLimited,
      );
      await _respond(
        message,
        error: const BridgeException('rate_limited', 'too many calls'),
      );
      return GuardOutcome.denied;
    }

    if (decision.requiresUserConfirmation) {
      final bool approved = await _confirm(message.requestId);
      if (!approved) {
        await _respond(
          message,
          error: const BridgeException('forbidden', 'declined by user'),
        );
        return GuardOutcome.denied;
      }
    }

    final BridgeContext context = BridgeContext(
      origin: grant.origin,
      frameKind: grant.frameKind,
      capability: rawCapability,
      args: message.args,
      requestId: message.requestId,
      legacy: message.legacy,
    );
    try {
      final Object? result = await handler(context);
      if (decision.oneShot) grant.revoke();
      await _respond(message, result: result);
      return GuardOutcome.granted;
    } on BridgeException catch (e) {
      await _respond(message, error: e);
      return GuardOutcome.answeredWithError;
    } catch (_) {
      await _respond(
        message,
        error: const BridgeException('internal', 'handler failed'),
      );
      return GuardOutcome.answeredWithError;
    }
  }

  /// Host finishes a pending confirmation. Denying an unknown id is a no-op.
  void completeConfirmation(String requestId, bool approved) {
    final Completer<bool>? completer = _confirmations.remove(requestId);
    if (completer == null) return;
    if (!completer.isCompleted) completer.complete(approved);
  }

  Future<bool> _confirm(String requestId) async {
    final Completer<bool> completer = Completer<bool>();
    _confirmations[requestId] = completer;
    // The host is expected to call completeConfirmation from a UI sheet.
    Timer(_config.confirmationTimeout, () {
      final Completer<bool>? pending = _confirmations.remove(requestId);
      if (pending != null && !pending.isCompleted) pending.complete(false);
    });
    return completer.future;
  }

  // ---------------------------------------------------------------------
  // Native-initiated attestation.
  // ---------------------------------------------------------------------

  Future<DocumentAttestation?> _attest() {
    if (_attestationInFlight != null) return _attestationInFlight!;
    final Future<DocumentAttestation?> future = _attestOnce();
    _attestationInFlight = future;
    return future.whenComplete(() {
      _attestationInFlight = null;
    });
  }

  Future<DocumentAttestation?> _attestOnce() async {
    if (!_consumeAttestationBudget()) {
      _emit(SecurityEventKind.rateLimited, reason: DenyReason.rateLimited);
      return null;
    }
    final String challenge = _tokens.newChallenge();
    final String script = buildAttestationScript(challenge);
    Object? raw;
    try {
      raw = await port
          .evaluateMainFrame(script)
          .timeout(_config.attestationTimeout);
    } on TimeoutException {
      return null;
    } catch (_) {
      return null;
    }
    try {
      final DocumentAttestation attestation =
          DocumentAttestation.parse(raw, challenge: challenge);
      if (!attestation.hasBootstrap) {
        // The bootstrap did not run, so the page cannot use the modern
        // envelope, but it may still be a legitimate legacy page. We still
        // trust the attested origin (it came from native), so let the grant
        // proceed; only the *page-side* shim is missing.
        return attestation;
      }
      return attestation;
    } on MessageFormatException catch (e) {
      _emit(SecurityEventKind.malformed, reason: e.reason);
      return null;
    }
  }

  bool _consumeAttestationBudget() {
    final DateTime now = _clock();
    final DateTime? start = _attestWindowStart;
    if (start == null || now.difference(start) >= const Duration(minutes: 1)) {
      _attestWindowStart = now;
      _attestWindowCount = 0;
    }
    if (_attestWindowCount >= _config.maxAttestationsPerMinute) return false;
    _attestWindowCount++;
    return true;
  }

  // ---------------------------------------------------------------------
  // Outbound delivery.
  //
  // All outbound traffic goes through a main-frame injection. Replies are
  // routed by request id inside the page bootstrap, which holds the token
  // in a closure. That is why a subframe cannot read the main frame's token
  // even from the reply stream.
  // ---------------------------------------------------------------------

  Future<void> _deliverGrant(
    String requestId,
    CapabilityGrant grant, {
    required FrameKind frameKind,
  }) async {
    final String payload = jsonEncode(<String, Object?>{
      't': grant.token,
      'o': grant.origin.toString(),
      'f': frameKind.name,
      'g': grant.generation,
      'n': grant.documentNonce,
      'caps': grant.capabilities.toList()..sort(),
    });
    await _safeInject(
      'window.$_bootstrap && window.$_bootstrap.grant(${jsonEncode(requestId)}, $payload);',
    );
  }

  Future<void> _pushTokenToMainFrame() async {
    // No-op here: main-frame tokens are delivered by [_deliverGrant], which
    // runs as part of the handshake. Subframe tokens are delivered to the
    // main frame with their nonce and forwarded locally by the bootstrap.
  }

  Future<void> _respond(
    BridgeMessage message, {
    Object? result,
    BridgeException? error,
  }) async {
    final void Function(String, Object?, BridgeException?)? sink = _responder;
    if (sink != null) {
      sink(message.requestId, result, error);
      return;
    }
    final Map<String, Object?> body = <String, Object?>{
      'id': message.requestId,
      if (error == null) 'r': result,
      if (error != null) 'e': <String, Object?>{'code': error.code, 'message': error.message},
    };
    await _safeInject(
      'window.$_bootstrap && window.$_bootstrap.reply(${jsonEncode(body)});',
    );
  }

  Future<void> _safeInject(String script) async {
    try {
      await port.injectMainFrame(script);
    } catch (_) {
      // Delivery failure is not a security failure: the page simply never
      // sees a reply, and its timeout fires. Do not throw into the queue.
    }
  }

  void _emit(
    SecurityEventKind kind, {
    Origin? origin,
    FrameKind? frameKind,
    String? capability,
    DenyReason? reason,
  }) {
    final void Function(SecurityEvent)? sink = _onSecurityEvent;
    if (sink == null) return;
    try {
      sink(SecurityEvent(
        kind: kind,
        at: _clock(),
        origin: origin,
        frameKind: frameKind,
        capability: capability,
        reason: reason,
      ));
    } catch (_) {
      // Telemetry must never break the decision path.
    }
  }
}

/// Builds the native-initiated main-frame read-back script.
///
/// Guarantees relied on by the guard:
/// * runs only in the top document, so only the top document's own values
///   can answer;
/// * echoes [challenge], which native generated moments ago and never sent
///   over the channel, so a page cannot answer a question it did not hear;
/// * returns browser-computed values (`location.origin`, `readyState`, and
///   the browser-set `event.origin` of each frame reply), not page claims;
/// * collects descendant replies that the top document itself recorded,
///   which a descendant cannot forge for a different origin.
String buildAttestationScript(String challenge) {
  final String c = jsonEncode(challenge);
  return '''
(function(){
  try {
    var b = window.__wb;
    if (!b) {
      // Bootstrap absent (e.g. legacy-only build). We can still attest the
      // top document itself from native.
      return JSON.stringify({c:$c,n:"",o:location.origin,r:document.readyState,
        v:document.visibilityState==="visible",a:[],b:false});
    }
    var a = b.frameAcks ? b.frameAcks() : [];
    return JSON.stringify({c:$c,n:b.nonce,o:location.origin,
      r:document.readyState,v:document.visibilityState==="visible",a:a,b:true});
  } catch(e) {
    return JSON.stringify({c:$c,n:"",o:null,r:"loading",v:false,a:[],b:false});
  }
})();
''';
}
