import 'dart:async';

import 'audit.dart';
import 'auth.dart';
import 'envelope.dart';
import 'errors.dart';
import 'origin.dart';
import 'policy.dart';
import 'response.dart';
import 'source.dart';
import 'tickets.dart';
import 'transport.dart';

class BridgeRequestContext {
  const BridgeRequestContext({
    required this.params,
    required this.source,
    required this.envelope,
  });

  final Map<String, dynamic> params;
  final VerifiedSource source;
  final BridgeEnvelope envelope;

  BridgeOrigin get trustedOrigin => source.origin;
}

typedef BridgeCapabilityHandler = FutureOr<Object?> Function(
  BridgeRequestContext context,
);

class RegisteredCapability {
  const RegisteredCapability({required this.policy, required this.handler});

  final CapabilityPolicy policy;
  final BridgeCapabilityHandler handler;
}

class BridgeDispatcher {
  BridgeDispatcher({
    required TicketLedger tickets,
    EnvelopeParser? parser,
    PolicyEvaluator? evaluator,
    this.audit = const NoopAuditSink(),
  })  : parser = parser ?? EnvelopeParser(),
        authenticator = BridgeAuthenticator(tickets),
        evaluator = evaluator ?? PolicyEvaluator();

  final EnvelopeParser parser;
  final BridgeAuthenticator authenticator;
  final PolicyEvaluator evaluator;
  final AuditSink audit;
  final Map<String, RegisteredCapability> _capabilities =
      <String, RegisteredCapability>{};

  void register(
    String capability,
    CapabilityPolicy policy,
    BridgeCapabilityHandler handler,
  ) {
    if (policy.capability != capability) {
      throw ArgumentError(
        'Capability key "$capability" does not match policy "${policy.capability}"',
      );
    }
    _capabilities[capability] =
        RegisteredCapability(policy: policy, handler: handler);
  }

  bool isRegistered(String capability) => _capabilities.containsKey(capability);

  Future<BridgeResponse> dispatch(IncomingTransportMessage input) async {
    String? requestId;
    String capability = '<unparsed>';

    try {
      final BridgeEnvelope envelope = parser.parse(input.body);
      requestId = envelope.requestId;
      capability = envelope.capability;

      final VerifiedSource source = authenticator.authenticate(input, envelope);

      final RegisteredCapability? registration =
          _capabilities[envelope.capability];
      if (registration == null) {
        throw BridgeException(
          BridgeErrorCode.unknownCapability,
          developerMessage: 'No native capability: ${envelope.capability}',
        );
      }

      final PolicyDecision decision = evaluator.evaluate(
        registration.policy,
        source,
      );
      if (!decision.allowed) {
        throw BridgeException(
          decision.error ?? BridgeErrorCode.originDenied,
          developerMessage: decision.reason ?? 'Policy denied',
        );
      }

      if (decision.hasAuditAdvisory) {
        audit.record(
          BridgeAuditEvent(
            at: DateTime.now(),
            webViewId: input.webViewId,
            decision: 'wouldDeny',
            capability: capability,
            origin: source.origin.value,
            frameKind: source.frameKind,
            assurance: source.assurance,
            reason:
                '${decision.advisoryError?.wireName}: ${decision.advisoryReason}',
            requestId: requestId,
          ),
        );
      }

      try {
        registration.policy.validator?.call(envelope.params);
      } on BridgeException {
        rethrow;
      } on Object catch (error) {
        throw BridgeException(
          BridgeErrorCode.invalidParams,
          developerMessage: 'Parameter validation failed',
          cause: error,
        );
      }

      final Object? data = await registration.handler(
        BridgeRequestContext(
          params: envelope.params,
          source: source,
          envelope: envelope,
        ),
      );

      audit.record(
        BridgeAuditEvent(
          at: DateTime.now(),
          webViewId: input.webViewId,
          decision: 'allow',
          capability: capability,
          origin: source.origin.value,
          frameKind: source.frameKind,
          assurance: source.assurance,
          requestId: requestId,
        ),
      );

      return BridgeResponse(
        requestId: requestId,
        ok: true,
        code: 'OK',
        data: data,
        legacyCallbackId: envelope.legacyCallbackId,
        legacySuccessCode: envelope.legacyMapping?.successWireCode,
        legacyEncoder: envelope.legacyMapping?.encodeSuccess,
      );
    } on BridgeException catch (error) {
      _deny(input, capability, requestId, error);
      return BridgeResponse(
        requestId: requestId,
        ok: false,
        code: error.code.wireName,
        // Public wire message stays stable and generic; developerMessage and
        // cause are only sent to the redacted native logs.
        message: error.code.wireName,
      );
    } on Object catch (error) {
      audit.record(
        BridgeAuditEvent(
          at: DateTime.now(),
          webViewId: input.webViewId,
          decision: 'error',
          capability: capability,
          reason: error.runtimeType.toString(),
          requestId: requestId,
        ),
      );
      return BridgeResponse(
        requestId: requestId,
        ok: false,
        code: BridgeErrorCode.internal.wireName,
        message: BridgeErrorCode.internal.wireName,
      );
    }
  }

  void _deny(
    IncomingTransportMessage input,
    String capability,
    String? requestId,
    BridgeException error,
  ) {
    final TrustedFrameMetadata? frame = input.frame;
    audit.record(
      BridgeAuditEvent(
        at: DateTime.now(),
        webViewId: input.webViewId,
        decision: 'deny',
        capability: capability,
        origin: frame?.origin.value,
        frameKind: frame?.frameKind,
        assurance: frame == null
            ? SourceAssurance.untrusted
            : SourceAssurance.nativeFrameMetadata,
        reason: error.developerMessage.isEmpty
            ? error.code.wireName
            : error.developerMessage,
        requestId: requestId,
      ),
    );
  }
}
