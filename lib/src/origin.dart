/// Canonical origin parsing and allow-list matching.
///
/// An [Origin] is the *only* thing this bridge trusts about a document's
/// identity. It is derived either from platform navigation signals (for
/// revocation) or from a main-frame `location.origin` read-back (for grants).
/// It is never derived from what page JavaScript claims in a message.
///
/// Parsing is deliberately strict: anything that a browser could interpret
/// differently from us is rejected (fail closed), because an allow-list match
/// on a string the browser disagrees with is a bypass waiting to happen.
library;

/// Default ports per scheme. A port equal to the scheme default is part of
/// the origin but is omitted from the canonical string.
const Map<String, int> _defaultPorts = <String, int>{'http': 80, 'https': 443};

/// Upper bound on the length of a URL we are willing to inspect. Real
/// navigation URLs are far shorter; oversized ones are noise or an attack.
const int kMaxUrlLength = 4096;

/// A browser origin: `scheme://host[:port]`.
///
/// Host is stored in the canonical form a browser reports through
/// `location.origin`: lowercase ASCII (punycode for IDNs), no trailing dot,
/// no percent-escapes, no surrounding brackets for IPv6.
final class Origin implements Comparable<Origin> {
  const Origin._({
    required this.scheme,
    required this.host,
    required this.port,
  });

  /// Either `http` or `https`.
  final String scheme;

  /// Canonical host. IPv6 hosts are stored without brackets (e.g. `::1`).
  final String host;

  /// Effective port, with the scheme default already substituted.
  final int port;

  /// Parses [raw] as a URL and returns its origin, or `null` when the value
  /// is not a plain `http(s)` URL with an unambiguous origin.
  ///
  /// Returns `null` for `about:blank`, `data:`, `blob:`, `file:` and
  /// `javascript:` documents. Those documents have an opaque origin
  /// (`"null"`) and must never satisfy an allow-list entry.
  static Origin? tryParse(Object? raw) {
    if (raw is! String) return null;
    if (raw.isEmpty || raw.length > kMaxUrlLength) return null;

    final Uri uri;
    try {
      uri = Uri.parse(raw);
    } on FormatException {
      return null;
    }

    if (uri.scheme != 'http' && uri.scheme != 'https') return null;

    // A URL carrying credentials is a phishing shape
    // (`https://activity.example.com@evil.example`). Depending on the
    // consumer, the host may be read either way, so refuse it outright.
    if (uri.hasAuthority == false || uri.userInfo.isNotEmpty) return null;

    final int port;
    if (uri.hasPort) {
      // Explicit `:0` is not a usable http port; `Uri` reports port 0 for
      // both "absent" and ":0", so `hasPort` is the only way to tell.
      if (uri.port <= 0 || uri.port > 65535) return null;
      port = uri.port;
    } else {
      port = _defaultPorts[uri.scheme]!;
    }

    final String? host = _canonicalHost(uri);
    if (host == null) return null;

    return Origin._(scheme: uri.scheme, host: host, port: port);
  }

  /// Returns `null` for any host we cannot canonicalise with certainty.
  static String? _canonicalHost(Uri uri) {
    String host = uri.host;
    if (host.isEmpty) return null;

    // Browsers ignore a single trailing dot (`example.com.` == `example.com`);
    // normalise so an allow-list entry cannot be defeated by adding one.
    if (host.endsWith('.')) host = host.substring(0, host.length - 1);
    if (host.isEmpty) return null;

    // `Uri` leaves percent-escapes in the host when it cannot decode them.
    // A host that still contains `%` is not canonical; reject.
    if (host.contains('%')) return null;

    // Non-ASCII hosts arrive percent-encoded. We refuse to guess at IDNA
    // mappings; operators must declare punycode (`xn--...`) explicitly.
    for (final int unit in host.codeUnits) {
      if (unit < 0x21 || unit > 0x7e) return null;
    }
    if (host.contains('_')) return null;

    if (host.contains(':')) {
      final String lower = host.toLowerCase();
      return _isIpv6(lower) ? lower : null;
    }
    final String lower = host.toLowerCase();
    if (_isIpv4(lower)) return lower;
    return _isDnsName(lower) ? lower : null;
  }

  /// Structural IPv6 check (brackets already stripped by [Uri]).
  ///
  /// We do not need to accept every legal form; we only need to be sure that
  /// whatever we accept is read identically by the platform. Anything odd
  /// fails closed. `host` is already lowercased.
  static bool _isIpv6(String host) {
    if (host.length > 45) return false;

    final int compression = host.indexOf('::');
    if (compression != -1 && compression != host.lastIndexOf('::')) {
      return false; // more than one `::`
    }

    final List<String> head;
    final List<String> tail;
    if (compression == -1) {
      head = host.split(':');
      tail = const <String>[];
      if (head.length != 8) return false;
    } else {
      final String before = host.substring(0, compression);
      final String after = host.substring(compression + 2);
      head = before.isEmpty ? const <String>[] : before.split(':');
      tail = after.isEmpty ? const <String>[] : after.split(':');
      if (head.length + tail.length >= 8) return false;
    }

    final List<String> groups = <String>[...head, ...tail];
    for (int i = 0; i < groups.length; i++) {
      final String group = groups[i];
      if (group.isEmpty || group.length > 4) return false;
      final bool isLast = i == groups.length - 1;
      if (isLast && compression == -1 && group.contains('.')) {
        // Embedded IPv4 consumes the slot of two hex groups.
        if (groups.length != 7 || !_isIpv4(group)) return false;
        continue;
      }
      if (!_RegExpHolder.hex.hasMatch(group)) return false;
    }
    return true;
  }

  static bool _isIpv4(String host) {
    final Match? match = _RegExpHolder.ipv4.firstMatch(host);
    if (match == null) return false;
    for (int i = 1; i <= 4; i++) {
      final String group = match.group(i)!;
      // Leading zeros make browsers disagree about the value (`010` can be
      // octal in legacy parsers), so such an address is not canonical.
      if (group.length > 1 && group.startsWith('0')) return false;
      final int value = int.parse(group);
      if (value > 255) return false;
    }
    return true;
  }

  static bool _isDnsName(String host) {
    if (host.length > 253) return false;
    final List<String> labels = host.split('.');
    if (labels.length < 2) {
      // A bare label can never match a real allow-list entry and is almost
      // always a parsing artifact.
      return false;
    }
    for (final String label in labels) {
      if (label.isEmpty || label.length > 63) return false;
      if (!_RegExpHolder.label.hasMatch(label)) return false;
      if (label.startsWith('-') || label.endsWith('-')) return false;
    }
    return true;
  }

  /// True when both origins are byte-identical after canonicalisation.
  bool sameAs(Origin other) =>
      scheme == other.scheme && host == other.host && port == other.port;

  @override
  int compareTo(Origin other) {
    final int byScheme = scheme.compareTo(other.scheme);
    if (byScheme != 0) return byScheme;
    final int byHost = host.compareTo(other.host);
    if (byHost != 0) return byHost;
    return port.compareTo(other.port);
  }

  @override
  bool operator ==(Object other) =>
      other is Origin && sameAs(other);

  @override
  int get hashCode => Object.hash(scheme, host, port);

  /// Canonical serialisation, identical in shape to `location.origin`.
  @override
  String toString() {
    final String hostPart = host.contains(':') ? '[$host]' : host;
    final bool showPort = port != _defaultPorts[scheme];
    return showPort ? '$scheme://$hostPart:$port' : '$scheme://$hostPart';
  }
}

/// An allow-list entry: either one exact origin, or a subdomain wildcard.
///
/// Wildcards are explicit and never match the apex domain unless asked:
/// `https://*.example.com` does **not** match `https://example.com`, and it
/// never matches `https://notexample.com`.
final class OriginPattern {
  const OriginPattern._({
    required this.origin,
    required this.includeSubdomains,
    required this.includeApex,
  });

  /// The literal origin for an exact pattern, or the base origin for a
  /// wildcard pattern (with the base host in [origin]).
  final Origin origin;

  /// True for `*.host` entries.
  final bool includeSubdomains;

  /// Whether the apex host is also covered by a wildcard entry. Declaration
  /// syntax `https://*.example.com` implies `false`; `https://example.com`
  /// is the way to say "apex only".
  final bool includeApex;

  /// Parses an allow-list entry.
  ///
  /// Accepted shapes:
  /// * `https://activity.example.com`
  /// * `https://activity.example.com:8443`
  /// * `https://*.example.com`       (any subdomain, not the apex)
  /// * `https://*.example.com+apex`  (any subdomain, and the apex)
  ///
  /// Throws [ArgumentError] for anything else. Misconfigured policy must
  /// fail at startup, not silently widen at runtime.
  factory OriginPattern.parse(String spec) {
    String raw = spec.trim();
    bool apex = false;
    if (raw.toLowerCase().endsWith('+apex')) {
      raw = raw.substring(0, raw.length - 5);
      apex = true;
    }

    final bool wildcard = raw.contains('*');
    if (!wildcard) {
      final Origin? exact = Origin.tryParse(raw);
      if (exact == null) {
        throw ArgumentError.value(spec, 'spec', 'not a canonical http(s) origin');
      }
      if (exact.host.split('.').length < 2) {
        throw ArgumentError.value(spec, 'spec', 'host must be a registrable name');
      }
      return OriginPattern._(
        origin: exact,
        includeSubdomains: false,
        includeApex: true,
      );
    }

    // Wildcard syntax is limited to a single leading `*.` label.
    final String hostWithWildcard = raw.split('://').skip(1).join('://');
    final String authority = hostWithWildcard.split('/').first;
    final String bareHost = authority.split(':').first;
    if (!bareHost.startsWith('*.') || bareHost.indexOf('*', 1) != -1) {
      throw ArgumentError.value(spec, 'spec', 'wildcard is only allowed as a leading "*." label');
    }
    final String baseHost = bareHost.substring(2);
    if (baseHost.isEmpty || baseHost.contains('*')) {
      throw ArgumentError.value(spec, 'spec', 'invalid wildcard host');
    }
    final Origin? base = Origin.tryParse(raw.replaceFirst('*.', ''));
    if (base == null) {
      throw ArgumentError.value(spec, 'spec', 'wildcard base is not a canonical origin');
    }
    if (base.host.split('.').length < 2) {
      throw ArgumentError.value(spec, 'spec', 'wildcard base must be a registrable name');
    }
    return OriginPattern._(
      origin: base,
      includeSubdomains: true,
      includeApex: apex,
    );
  }

  /// Whether [candidate] is covered by this entry.
  bool matches(Origin candidate) {
    if (candidate.scheme != origin.scheme || candidate.port != origin.port) {
      return false;
    }
    if (!includeSubdomains) return candidate.host == origin.host;
    if (includeApex && candidate.host == origin.host) return true;
    // Must be a strict label-boundary suffix: `evil-example.com` and
    // `example.com.evil.com` both fail.
    return candidate.host.endsWith('.${origin.host}');
  }

  /// Higher is more specific; used to pick the most restrictive matching
  /// grant instead of letting grant order decide security.
  int get specificity {
    if (includeSubdomains) {
      return includeApex ? 1 : 2;
    }
    return 3;
  }

  @override
  String toString() {
    final String hostPart = includeSubdomains
        ? '*.${origin.host}${includeApex ? '+apex' : ''}'
        : origin.host;
    final String portPart =
        origin.port == _defaultPorts[origin.scheme] ? '' : ':${origin.port}';
    return '${origin.scheme}://$hostPart$portPart';
  }
}

/// Small holder so the RegExps are compiled once.
abstract final class _RegExpHolder {
  static final RegExp ipv4 = RegExp(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$');
  static final RegExp hex = RegExp(r'^[0-9a-f]+$');
  static final RegExp label = RegExp(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$');
}
