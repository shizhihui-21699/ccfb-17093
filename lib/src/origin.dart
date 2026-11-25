import 'errors.dart';

/// Canonical web origin: scheme + host + effective port.
///
/// This is deliberately not a substring/URL-prefix check.
class BridgeOrigin {
  const BridgeOrigin._(this._uri, this.value);

  factory BridgeOrigin.parse(String raw) {
    final String trimmed = raw.trim();
    if (trimmed.isEmpty) {
      throw BridgeException(
        BridgeErrorCode.invalidMessage,
        developerMessage: 'Origin is empty',
      );
    }

    final Uri uri = Uri.parse(trimmed);
    if (!uri.hasScheme || (uri.scheme != 'https' && uri.scheme != 'http')) {
      throw BridgeException(
        BridgeErrorCode.invalidMessage,
        developerMessage: 'Only http/https origins are supported',
      );
    }
    if (uri.host.isEmpty) {
      throw BridgeException(
        BridgeErrorCode.invalidMessage,
        developerMessage: 'Origin host is empty',
      );
    }
    if (uri.userInfo.isNotEmpty) {
      throw BridgeException(
        BridgeErrorCode.invalidMessage,
        developerMessage: 'User info is not allowed in an origin',
      );
    }

    // Uri.origin strips path/query/fragment and canonicalizes default ports.
    final String value = uri.origin;
    return BridgeOrigin._(uri, value);
  }

  factory BridgeOrigin.fromUri(Uri uri) => BridgeOrigin.parse(uri.toString());

  final Uri _uri;
  final String value;

  String get scheme => _uri.scheme;

  String get host => _uri.host.toLowerCase();

  int get port {
    if (_uri.hasPort) return _uri.port;
    return scheme == 'https' ? 443 : 80;
  }

  @override
  bool operator ==(Object other) =>
      other is BridgeOrigin && other.value == value;

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => value;
}

/// Matches one exact origin or a carefully bounded left-side wildcard.
abstract class OriginPattern {
  bool matches(BridgeOrigin origin);

  factory OriginPattern.parse(String raw) {
    final String pattern = raw.trim();
    final int schemeEnd = pattern.indexOf('://');
    if (schemeEnd <= 0) {
      throw FormatException('Invalid origin pattern: $raw');
    }

    final String scheme = pattern.substring(0, schemeEnd).toLowerCase();
    if (scheme != 'https' && scheme != 'http') {
      throw FormatException('Unsupported origin pattern scheme: $raw');
    }

    String rest = pattern.substring(schemeEnd + 3);
    String? portText;
    final int colon = rest.indexOf(':');
    if (colon >= 0) {
      portText = rest.substring(colon + 1);
      rest = rest.substring(0, colon);
    }

    if (rest.contains('/') || rest.contains('?') || rest.contains('#')) {
      throw FormatException('Origin pattern must not contain a path: $raw');
    }

    final int? port = portText == null ? null : int.tryParse(portText);
    if (portText != null && port == null) {
      throw FormatException('Invalid port in origin pattern: $raw');
    }

    if (rest.startsWith('*.')) {
      final String suffix = rest.substring(1).toLowerCase(); // .example.com
      if (suffix.length <= 1 || suffix.contains('*')) {
        throw FormatException('Invalid wildcard origin pattern: $raw');
      }
      return WildcardOriginPattern._(scheme, suffix, port);
    }

    if (rest.contains('*')) {
      throw FormatException(
          'Only leading *.host wildcards are supported: $raw');
    }

    final BridgeOrigin exact = BridgeOrigin.parse(
      '$scheme://$rest${port == null ? '' : ':$port'}',
    );
    return ExactOriginPattern._(exact);
  }
}

class ExactOriginPattern implements OriginPattern {
  const ExactOriginPattern._(this.origin);

  final BridgeOrigin origin;

  @override
  bool matches(BridgeOrigin candidate) => candidate == origin;

  @override
  String toString() => origin.value;
}

class WildcardOriginPattern implements OriginPattern {
  const WildcardOriginPattern._(this.scheme, this.dotHostSuffix, this.port);

  final String scheme;

  /// Includes the leading dot, e.g. `.example.com`.
  final String dotHostSuffix;
  final int? port;

  @override
  bool matches(BridgeOrigin candidate) {
    if (candidate.scheme != scheme) return false;

    final int effectivePatternPort = port ?? (scheme == 'https' ? 443 : 80);
    if (candidate.port != effectivePatternPort) return false;

    final String host = candidate.host;
    return host.endsWith(dotHostSuffix) && host != dotHostSuffix.substring(1);
  }

  @override
  String toString() =>
      '$scheme://*$dotHostSuffix${port == null ? '' : ':$port'}';
}
