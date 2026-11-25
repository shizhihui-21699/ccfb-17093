/// Maps the pre-security wire protocol to stable capability names.
///
/// One implementation can encode the dozens of already-shipped activity-page
/// dialects here; pages themselves do not need to be rewritten.
class LegacyActionMapping {
  const LegacyActionMapping({
    required this.actions,
    required this.capability,
    this.decodeParams,
    this.encodeSuccess,
    this.successWireCode = 0,
  });

  final Set<String> actions;
  final String capability;

  /// Converts the complete legacy JSON object into capability parameters.
  final Map<String, dynamic> Function(Map<String, dynamic> raw)? decodeParams;

  /// Converts the native capability result back to the old page response shape.
  final Object? Function(Object? result)? encodeSuccess;

  /// Many old pages treat `code: 0` / `code: 200` as success.
  final int successWireCode;
}

class LegacyActionRegistry {
  LegacyActionRegistry([Iterable<LegacyActionMapping> mappings = const []]) {
    for (final LegacyActionMapping mapping in mappings) {
      for (final String action in mapping.actions) {
        _byAction[action] = mapping;
      }
    }
  }

  final Map<String, LegacyActionMapping> _byAction =
      <String, LegacyActionMapping>{};

  LegacyActionMapping? forAction(String? action) =>
      action == null ? null : _byAction[action];

  Set<String> get knownActions => _byAction.keys.toSet();
}
