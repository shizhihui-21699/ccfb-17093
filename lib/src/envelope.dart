import 'dart:convert';

import 'errors.dart';
import 'legacy.dart';

class BridgeEnvelope {
  const BridgeEnvelope({
    required this.requestId,
    required this.capability,
    required this.params,
    required this.ticket,
    required this.rawBody,
    this.legacyAction,
    this.legacyCallbackId,
    this.legacyMapping,
  });

  final String requestId;
  final String capability;
  final Map<String, dynamic> params;
  final String? ticket;
  final Object? rawBody;
  final String? legacyAction;
  final String? legacyCallbackId;
  final LegacyActionMapping? legacyMapping;

  bool get isLegacy => legacyAction != null;
}

class EnvelopeParser {
  EnvelopeParser({LegacyActionRegistry? legacy})
      : legacy = legacy ?? LegacyActionRegistry();

  final LegacyActionRegistry legacy;
  int _sequence = 0;

  BridgeEnvelope parse(Object? body) {
    final Object? decoded = _decodeBody(body);
    final Map<String, dynamic> root = _asStringMap(decoded);

    // The injected compatibility script wraps old JSON in {v:'2', legacy:...}.
    // This must be recognized before the ordinary v2 capability envelope.
    final Object? wrappedLegacy = root['legacy'];
    if (wrappedLegacy != null) {
      final Object? decodedLegacy = wrappedLegacy is String
          ? _decodeWrappedLegacyString(wrappedLegacy)
          : wrappedLegacy;
      final Map<String, dynamic> legacyRaw = _asStringMap(decodedLegacy);
      return _parseLegacy(
        legacyRaw,
        outer: root,
        rawBody: body,
      );
    }

    final String? version = root['v']?.toString();
    final bool isV2 = version == '2' || root.containsKey('capability');

    if (isV2) {
      return _parseV2(root, body);
    }

    // Direct legacy call. Strong native frame metadata can still authenticate
    // it even when the page was not transformed or the wrapper was bypassed.
    return _parseLegacy(root, outer: null, rawBody: body);
  }

  Object? _decodeWrappedLegacyString(String text) {
    try {
      return _jsonDecode(text);
    } on FormatException catch (error) {
      throw BridgeException(
        BridgeErrorCode.invalidMessage,
        developerMessage: 'Wrapped legacy message is not valid JSON',
        cause: error,
      );
    }
  }

  Object? _decodeBody(Object? body) {
    if (body is Map) return body;
    if (body is! String) {
      throw BridgeException(
        BridgeErrorCode.invalidMessage,
        developerMessage: 'Channel body is neither JSON string nor map',
      );
    }

    final String text = body.trim();
    if (text.isEmpty) {
      throw BridgeException(
        BridgeErrorCode.invalidMessage,
        developerMessage: 'Empty channel message',
      );
    }

    try {
      return _jsonDecode(text);
    } on FormatException catch (error) {
      // Some old channels send a bare action name.
      final LegacyActionMapping? mapping = legacy.forAction(text);
      if (mapping != null) {
        return <String, dynamic>{'action': text};
      }
      throw BridgeException(
        BridgeErrorCode.invalidMessage,
        developerMessage: 'Message is not valid JSON: ${error.message}',
        cause: error,
      );
    }
  }

  Object? _jsonDecode(String text) {
    try {
      return jsonDecode(text);
    } on FormatException {
      rethrow;
    }
  }

  BridgeEnvelope _parseV2(Map<String, dynamic> root, Object? rawBody) {
    final String? capability = root['capability']?.toString();
    if (capability == null || capability.isEmpty) {
      throw BridgeException(
        BridgeErrorCode.invalidMessage,
        developerMessage: 'Missing capability',
      );
    }

    final Object? rawParams = root['params'] ?? root['data'];
    final Map<String, dynamic> params =
        rawParams == null ? <String, dynamic>{} : _asStringMap(rawParams);

    return BridgeEnvelope(
      requestId: _requestId(root['id'] ?? root['requestId']),
      capability: capability,
      params: params,
      ticket: root['ticket']?.toString(),
      rawBody: rawBody,
    );
  }

  BridgeEnvelope _parseLegacy(
    Map<String, dynamic> raw, {
    required Map<String, dynamic>? outer,
    required Object? rawBody,
  }) {
    final String? action = (raw['action'] ??
            raw['method'] ??
            raw['type'] ??
            raw['name'] ??
            raw['api'])
        ?.toString();
    final LegacyActionMapping? mapping = legacy.forAction(action);

    if (mapping == null) {
      throw BridgeException(
        BridgeErrorCode.unknownCapability,
        developerMessage: 'Unknown legacy action: $action',
      );
    }

    final Map<String, dynamic> params = mapping.decodeParams != null
        ? mapping.decodeParams!(raw)
        : _defaultLegacyParams(raw);

    // Never read a legacy business field named `ticket` as the authentication
    // ticket: coupon/lottery protocols commonly use that key. The compatibility
    // wrapper puts the auth ticket in the outer v2 envelope or __bridgeTicket.
    final Object? ticketValue = outer?['ticket'] ??
        outer?['__bridgeTicket'] ??
        raw['__bridgeTicket'] ??
        raw['__ticket'];
    params
      ..remove('__bridgeTicket')
      ..remove('__ticket');
    final Object? requestIdValue =
        outer?['id'] ?? outer?['requestId'] ?? raw['requestId'];
    final Object? callbackId =
        raw['callbackId'] ?? raw['callbackID'] ?? raw['cbId'] ?? raw['id'];

    return BridgeEnvelope(
      requestId: _requestId(requestIdValue),
      capability: mapping.capability,
      params: params,
      ticket: ticketValue?.toString(),
      rawBody: rawBody,
      legacyAction: action,
      legacyCallbackId: callbackId?.toString(),
      legacyMapping: mapping,
    );
  }

  Map<String, dynamic> _defaultLegacyParams(Map<String, dynamic> raw) {
    final Object? nested =
        raw['params'] ?? raw['data'] ?? raw['payload'] ?? raw['bizParams'];
    if (nested == null) return Map<String, dynamic>.of(raw);
    if (nested is String && nested.isNotEmpty) {
      try {
        return _asStringMap(jsonDecode(nested));
      } on Object {
        return <String, dynamic>{'value': nested};
      }
    }
    return _asStringMap(nested);
  }

  String _requestId(Object? value) {
    if (value != null && value.toString().isNotEmpty) return value.toString();
    _sequence += 1;
    return 'req-$_sequence';
  }

  static Map<String, dynamic> _asStringMap(Object? value) {
    if (value is Map<String, dynamic>) return value;
    if (value is Map) {
      return value.map(
        (Object? key, Object? v) =>
            MapEntry<String, dynamic>(key.toString(), v),
      );
    }
    throw BridgeException(
      BridgeErrorCode.invalidParams,
      developerMessage: 'Expected JSON object, got ${value.runtimeType}',
    );
  }
}
