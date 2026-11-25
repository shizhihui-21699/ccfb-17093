import 'errors.dart';
import 'origin.dart';
import 'source.dart';

class RateLimit {
  const RateLimit({required this.maxCalls, required this.window});

  final int maxCalls;
  final Duration window;
}

class RateLimiter {
  final Map<String, List<DateTime>> _hits = <String, List<DateTime>>{};

  bool allow(String key, RateLimit limit, DateTime now) {
    final List<DateTime> hits = _hits.putIfAbsent(key, () => <DateTime>[]);
    final DateTime cutoff = now.subtract(limit.window);
    hits.removeWhere((DateTime t) => !t.isAfter(cutoff));

    if (hits.length >= limit.maxCalls) return false;
    hits.add(now);
    return true;
  }

  void reset() => _hits.clear();
}

class CapabilityPolicy {
  CapabilityPolicy({
    required this.capability,
    Iterable<String> mainFrameOrigins = const <String>[],
    Iterable<String> childFrameOrigins = const <String>[],
    Iterable<String> topLevelAncestorOrigins = const <String>[],
    this.minimumAssurance = SourceAssurance.nativeFrameMetadata,
    this.rateLimit,
    this.validator,
  })  : mainFrameOrigins = mainFrameOrigins.map(OriginPattern.parse).toSet(),
        childFrameOrigins = childFrameOrigins.map(OriginPattern.parse).toSet(),
        topLevelAncestorOrigins =
            topLevelAncestorOrigins.map(OriginPattern.parse).toSet();

  final String capability;
  final Set<OriginPattern> mainFrameOrigins;
  final Set<OriginPattern> childFrameOrigins;

  /// If non-empty, a child frame's top-level ancestor must match one pattern.
  /// The first entry in [VerifiedSource.ancestorChain] is treated as top.
  final Set<OriginPattern> topLevelAncestorOrigins;
  final SourceAssurance minimumAssurance;
  final RateLimit? rateLimit;
  final void Function(Map<String, dynamic> params)? validator;

  bool allowsMainOrigin(BridgeOrigin origin) =>
      mainFrameOrigins.any((OriginPattern p) => p.matches(origin));

  bool allowsChildOrigin(BridgeOrigin origin) =>
      childFrameOrigins.any((OriginPattern p) => p.matches(origin));

  bool allowsTopAncestor(List<BridgeOrigin> chain) {
    if (topLevelAncestorOrigins.isEmpty) return true;
    if (chain.isEmpty) return false;
    final BridgeOrigin top = chain.first;
    return topLevelAncestorOrigins.any((OriginPattern p) => p.matches(top));
  }
}

enum PolicyMode {
  /// Deny and do not invoke the handler.
  enforce,

  /// Temporarily allow but emit a `wouldDeny` audit event. Use only during
  /// origin/frame inventory rollout; never leave critical capabilities in this
  /// mode permanently.
  auditOnly,
}

class PolicyDecision {
  const PolicyDecision.allow()
      : allowed = true,
        error = null,
        reason = null,
        advisoryError = null,
        advisoryReason = null;

  const PolicyDecision.deny(this.error, this.reason)
      : allowed = false,
        advisoryError = null,
        advisoryReason = null;

  const PolicyDecision.auditOnlyAllow(this.advisoryError, this.advisoryReason)
      : allowed = true,
        error = null,
        reason = null;

  final bool allowed;
  final BridgeErrorCode? error;
  final String? reason;
  final BridgeErrorCode? advisoryError;
  final String? advisoryReason;

  bool get hasAuditAdvisory => advisoryError != null;
}

class PolicyEvaluator {
  PolicyEvaluator({
    RateLimiter? rateLimiter,
    this.mode = PolicyMode.enforce,
  }) : rateLimiter = rateLimiter ?? RateLimiter();

  final RateLimiter rateLimiter;
  final PolicyMode mode;

  PolicyDecision _reject(BridgeErrorCode code, String reason) {
    return mode == PolicyMode.enforce
        ? PolicyDecision.deny(code, reason)
        : PolicyDecision.auditOnlyAllow(code, reason);
  }

  PolicyDecision evaluate(
    CapabilityPolicy policy,
    VerifiedSource source, {
    DateTime? now,
  }) {
    if (!source.assurance.atLeast(policy.minimumAssurance)) {
      return _reject(
        BridgeErrorCode.assuranceInsufficient,
        'Need ${policy.minimumAssurance.name}, got ${source.assurance.name}',
      );
    }

    switch (source.frameKind) {
      case FrameKind.unknown:
        return _reject(
          BridgeErrorCode.frameDenied,
          'Frame identity is unknown',
        );
      case FrameKind.mainFrame:
        if (!policy.allowsMainOrigin(source.origin)) {
          return _reject(
            BridgeErrorCode.originDenied,
            'Main origin ${source.origin} is not allowed for ${policy.capability}',
          );
        }
      case FrameKind.childFrame:
        if (!policy.allowsChildOrigin(source.origin)) {
          return _reject(
            BridgeErrorCode.frameDenied,
            'Child origin ${source.origin} is not allowed for ${policy.capability}',
          );
        }
        if (!policy.allowsTopAncestor(source.ancestorChain)) {
          return _reject(
            BridgeErrorCode.frameDenied,
            'Child frame top-level ancestor is not allowed',
          );
        }
    }

    final RateLimit? limit = policy.rateLimit;
    if (limit != null) {
      final DateTime time = now ?? DateTime.now();
      final String key =
          '${source.webViewId}|${source.origin.value}|${source.frameKind.name}|${policy.capability}';
      if (!rateLimiter.allow(key, limit, time)) {
        return _reject(
          BridgeErrorCode.rateLimited,
          'Capability rate limit exceeded',
        );
      }
    }

    return const PolicyDecision.allow();
  }
}
