/// Per-capability access policy.
///
/// The policy answers one question: *may this exact origin, in this exact
/// kind of frame, reach this capability?* Everything else in the bridge
/// (tokens, generations, evidence) exists to make sure the origin and frame
/// kind being asked about are truthful.
///
/// Two rules matter and are easy to get wrong:
///
/// 1. **The most restrictive matching rule wins.** Config order must never
///    decide security, so when several rules match the same
///    `(capability, origin, frame)` tuple the resolver picks the highest
///    risk, then the strictest options. An operator adding a narrow denial
///    for one path cannot accidentally leave a wide grant open.
/// 2. **An unknown capability is denied.** There is no "default allow"
///    branch anywhere in this file.
library;

import 'message.dart';
import 'origin.dart';

/// How dangerous a capability is. Drives logging, confirmation prompts and
/// what an automated test suite must cover.
enum RiskLevel {
  /// UI-only, no user data leaves the page.
  low,

  /// Touches user data or money, but reversibly.
  medium,

  /// Reads credentials or personal data, or spends money irreversibly.
  high,
}

/// One capability grant rule.
final class CapabilityRule {
  const CapabilityRule({
    required this.capability,
    required this.origins,
    required this.frameKinds,
    this.risk = RiskLevel.medium,
    this.requiresUserConfirmation = false,
    this.maxCallsPerMinute = 60,
    this.oneShot = false,
    this.legacyActions = const <String>[],
  });

  /// Canonical capability name, e.g. `auth.token`. Legacy action names are
  /// translated to this before policy runs.
  final String capability;

  /// Origins permitted to reach [capability]. Empty means "nobody" — a rule
  /// with no origins is a deliberate kill switch and is allowed.
  final List<OriginPattern> origins;

  /// Frame kinds permitted to reach [capability]. A main-frame-only
  /// capability must list only [FrameKind.main].
  final Set<FrameKind> frameKinds;

  final RiskLevel risk;

  /// When true the host must show a native confirmation sheet and the call
  /// is answered only after [BridgeGuard.confirm].
  final bool requiresUserConfirmation;

  /// Per-grant rate limit.
  final int maxCallsPerMinute;

  /// When true the grant is consumed by a successful call.
  final bool oneShot;

  /// Legacy action names (already shipped in activity pages) that map here.
  /// Keeping them in the rule — not in a global table — means a legacy page
  /// gains nothing beyond the rule it was already granted.
  final List<String> legacyActions;

  /// Specificity used when several rules match. Higher is narrower.
  int get specificity =>
      origins.isEmpty ? 0 : origins.map((OriginPattern p) => p.specificity).reduce(_min);

  CapabilityRule _stricterThan(CapabilityRule other) {
    if (risk != other.risk) {
      return risk.index > other.risk.index ? this : other;
    }
    if (requiresUserConfirmation != other.requiresUserConfirmation) {
      return requiresUserConfirmation ? this : other;
    }
    if (oneShot != other.oneShot) return oneShot ? this : other;
    return maxCallsPerMinute <= other.maxCallsPerMinute ? this : other;
  }

  static int _min(int a, int b) => a < b ? a : b;

  @override
  String toString() => 'CapabilityRule($capability, risk=${risk.name}, '
      'frames=${frameKinds.map((FrameKind k) => k.name).join(",")})';
}

/// The compiled result of a policy lookup.
final class CapabilityDecision {
  const CapabilityDecision._({
    required this.rule,
    required this.matchedOrigin,
  });

  final CapabilityRule rule;
  final OriginPattern matchedOrigin;

  RiskLevel get risk => rule.risk;
  bool get requiresUserConfirmation => rule.requiresUserConfirmation;
  bool get oneShot => rule.oneShot;
  int get maxCallsPerMinute => rule.maxCallsPerMinute;
}

/// Compiled, immutable policy.
///
/// Build it once at app start. Construction validates the whole config so a
/// typo fails the app launch (in debug and CI) instead of silently widening
/// access at runtime.
final class BridgePolicy {
  BridgePolicy._({
    required this.rules,
    required this.allowedTopOrigins,
    required this.allowedSubframeOrigins,
    required this.legacyEnabled,
    required Map<String, CapabilityRule> legacyActions,
  }) : _byCapability = _index(rules),
       _legacyActions = legacyActions;

  /// Compiles and validates the configuration.
  ///
  /// Throws [ArgumentError] on duplicate capability names, duplicate legacy
  /// action mappings, empty capability names, or a policy that allows no
  /// top-level origin at all (which would make the bridge dead — almost
  /// always a configuration mistake, so we refuse to start).
  factory BridgePolicy.compile({
    required List<CapabilityRule> rules,
    required List<OriginPattern> allowedTopOrigins,
    List<OriginPattern> allowedSubframeOrigins = const <OriginPattern>[],
    bool legacyEnabled = true,
  }) {
    final Map<String, CapabilityRule> legacy = <String, CapabilityRule>{};
    final Set<String> seen = <String>{};
    for (final CapabilityRule rule in rules) {
      if (rule.capability.isEmpty || rule.capability.length > 64) {
        throw ArgumentError.value(rule.capability, 'capability', 'invalid name');
      }
      if (!seen.add(rule.capability)) {
        throw ArgumentError.value(
          rule.capability,
          'rules',
          'duplicate capability rule; merge them into one',
        );
      }
      for (final String action in rule.legacyActions) {
        final CapabilityRule? existing = legacy[action];
        if (existing != null && existing.capability != rule.capability) {
          throw ArgumentError.value(
            action,
            'legacyActions',
            'already mapped to ${existing.capability}',
          );
        }
        legacy[action] = rule;
      }
    }
    if (allowedTopOrigins.isEmpty) {
      throw ArgumentError.value(
        allowedTopOrigins,
        'allowedTopOrigins',
        'at least one top-level origin is required',
      );
    }
    return BridgePolicy._(
      rules: List<CapabilityRule>.unmodifiable(rules),
      allowedTopOrigins: List<OriginPattern>.unmodifiable(allowedTopOrigins),
      allowedSubframeOrigins:
          List<OriginPattern>.unmodifiable(allowedSubframeOrigins),
      legacyEnabled: legacyEnabled,
      legacyActions: legacy,
    );
  }

  /// All known rules, for tooling and audit output.
  final List<CapabilityRule> rules;

  /// Origins allowed to host the embedded activity container at all.
  final List<OriginPattern> allowedTopOrigins;

  /// Origins allowed to receive a delegated sub-frame grant. Checked **in
  /// addition to** [allowedTopOrigins] for the document hosting the subframe.
  final List<OriginPattern> allowedSubframeOrigins;

  /// Whether legacy envelopes are accepted at all. Turning this off is the
  /// end state of the migration; leaving it on keeps shipped pages working.
  final bool legacyEnabled;

  final Map<String, List<CapabilityRule>> _byCapability;
  final Map<String, CapabilityRule> _legacyActions;

  /// Whether [origin] may host the container as the top-level document.
  bool allowsTopOrigin(Origin origin) =>
      allowedTopOrigins.any((OriginPattern p) => p.matches(origin));

  /// Whether [origin] may receive a delegated sub-frame grant **inside**
  /// [topOrigin]. A subframe origin is never trusted on its own.
  bool allowsSubframeOrigin(Origin origin, Origin topOrigin) =>
      allowedTopOrigins.any((OriginPattern p) => p.matches(topOrigin)) &&
      allowedSubframeOrigins.any((OriginPattern p) => p.matches(origin));

  /// All capability names reachable by [origin] in [frameKind].
  ///
  /// Used to compute a grant's initial scope. A grant can never hold more
  /// than this at mint time, and every call re-checks the rule anyway.
  Set<String> capabilitiesFor(Origin origin, FrameKind frameKind) {
    final Set<String> caps = <String>{};
    for (final CapabilityRule rule in rules) {
      if (!rule.frameKinds.contains(frameKind)) continue;
      if (rule.origins.any((OriginPattern p) => p.matches(origin))) {
        caps.add(rule.capability);
      }
    }
    return caps;
  }

  /// Resolves a capability for an authenticated (origin, frame) pair.
  ///
  /// Returns `null` when no rule matches — the caller denies.
  CapabilityDecision? resolve(
    String capability,
    Origin origin,
    FrameKind frameKind,
  ) {
    final List<CapabilityRule>? candidates = _byCapability[capability];
    if (candidates == null) return null;

    CapabilityRule? chosen;
    OriginPattern? chosenOrigin;
    for (final CapabilityRule rule in candidates) {
      if (!rule.frameKinds.contains(frameKind)) continue;
      for (final OriginPattern pattern in rule.origins) {
        if (!pattern.matches(origin)) continue;
        if (chosen == null) {
          chosen = rule;
          chosenOrigin = pattern;
          continue;
        }
        final CapabilityRule resolved = chosen._stricterThan(rule);
        if (identical(resolved, rule)) {
          chosen = rule;
          chosenOrigin = pattern;
        }
      }
    }
    if (chosen == null || chosenOrigin == null) return null;
    return CapabilityDecision._(rule: chosen, matchedOrigin: chosenOrigin);
  }

  /// Maps a legacy action name to its capability, or `null`.
  ///
  /// Only consulted when [legacyEnabled]; the resulting capability still
  /// goes through [resolve], so a legacy page cannot reach more than the
  /// rule it maps to.
  String? capabilityForLegacyAction(String action) {
    if (!legacyEnabled) return null;
    return _legacyActions[action]?.capability;
  }

  /// Legacy action names known to the current policy, for migration tooling.
  Set<String> get knownLegacyActions =>
      legacyEnabled ? _legacyActions.keys.toSet() : <String>{};

  /// Like [resolve], but ignores frame kind. Used only to distinguish "this
  /// frame may not ask" from "nobody may ask" when building an error for the
  /// page; the boolean it enables is diagnostics, not authorization.
  CapabilityDecision? resolveAnyFrame(String capability, Origin origin) {
    final List<CapabilityRule>? candidates = _byCapability[capability];
    if (candidates == null) return null;
    for (final CapabilityRule rule in candidates) {
      for (final OriginPattern pattern in rule.origins) {
        if (pattern.matches(origin)) {
          return CapabilityDecision._(rule: rule, matchedOrigin: pattern);
        }
      }
    }
    return null;
  }

  /// Lists every `(rule, pattern)` pair that admits [capability] for
  /// [origin], most restrictive first, for auditing tools.
  List<CapabilityRule> matchingRules(String capability, Origin origin) {
    final List<CapabilityRule>? candidates = _byCapability[capability];
    if (candidates == null) return const <CapabilityRule>[];
    final List<CapabilityRule> matches = candidates
        .where((CapabilityRule r) =>
            r.origins.any((OriginPattern p) => p.matches(origin)))
        .toList()
      ..sort((CapabilityRule a, CapabilityRule b) {
        final int byRisk = b.risk.index.compareTo(a.risk.index);
        if (byRisk != 0) return byRisk;
        return b.specificity.compareTo(a.specificity);
      });
    return matches;
  }

  /// A grant's scope consists only of capabilities that are (a) matched by a
  /// rule for this origin, and (b) actually backed by a registered handler.
  Set<String> effectiveCapabilities(
    Origin origin,
    FrameKind frameKind,
    Set<String> registered,
  ) {
    final Set<String> allowed = capabilitiesFor(origin, frameKind);
    return allowed.where(registered.contains).toSet();
  }

  static Map<String, List<CapabilityRule>> _index(List<CapabilityRule> rules) {
    final Map<String, List<CapabilityRule>> index =
        <String, List<CapabilityRule>>{};
    for (final CapabilityRule rule in rules) {
      (index[rule.capability] ??= <CapabilityRule>[]).add(rule);
    }
    return index;
  }
}
