import 'source.dart';

class BridgeAuditEvent {
  const BridgeAuditEvent({
    required this.at,
    required this.webViewId,
    required this.decision,
    required this.capability,
    this.origin,
    this.frameKind,
    this.assurance,
    this.reason,
    this.requestId,
  });

  final DateTime at;
  final String webViewId;
  final String decision; // allow | deny | error
  final String capability;
  final String? origin;
  final FrameKind? frameKind;
  final SourceAssurance? assurance;
  final String? reason;
  final String? requestId;

  Map<String, Object?> toJson() => <String, Object?>{
        'at': at.toIso8601String(),
        'webViewId': webViewId,
        'decision': decision,
        'capability': capability,
        'origin': origin,
        'frame': frameKind?.name,
        'assurance': assurance?.name,
        'reason': reason,
        'requestId': requestId,
      };
}

abstract class AuditSink {
  void record(BridgeAuditEvent event);
}

class InMemoryAuditSink implements AuditSink {
  final List<BridgeAuditEvent> events = <BridgeAuditEvent>[];

  @override
  void record(BridgeAuditEvent event) => events.add(event);

  List<BridgeAuditEvent> get denials =>
      events.where((BridgeAuditEvent e) => e.decision == 'deny').toList();
}

/// Redacts all parameters and results by design. Log transport should also
/// redact the raw channel payload because legacy messages may contain PII.
class NoopAuditSink implements AuditSink {
  const NoopAuditSink();

  @override
  void record(BridgeAuditEvent event) {}
}
