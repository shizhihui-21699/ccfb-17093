import 'dart:convert';

class BridgeResponse {
  const BridgeResponse({
    required this.requestId,
    required this.ok,
    required this.code,
    this.data,
    this.message,
    this.legacyCallbackId,
    this.legacySuccessCode,
    this.legacyEncoder,
  });

  final String? requestId;
  final bool ok;
  final String code;
  final Object? data;
  final String? message;
  final String? legacyCallbackId;
  final int? legacySuccessCode;
  final Object? Function(Object? result)? legacyEncoder;

  Map<String, dynamic> toJson() {
    Object? payload = data;
    if (ok && legacyEncoder != null) {
      payload = legacyEncoder!(data);
    }

    return <String, dynamic>{
      'requestId': requestId,
      'ok': ok,
      'code': code,
      if (message != null) 'message': message,
      if (payload != null) 'data': payload,
      if (legacyCallbackId != null) 'legacyCallbackId': legacyCallbackId,
    };
  }

  /// Calls the injected response router. JSON encoding makes this safe against
  /// script injection through string data.
  String toJavaScript({String global = '__lifeBridgeReceive'}) {
    final String json = jsonEncode(toJson());
    return 'window.$global && window.$global($json);';
  }

  /// Old pages often expect `{code:0,...}` rather than `{ok:true,...}`.
  String toLegacyJavaScript({
    required String callbackDispatcher,
  }) {
    final Object? encoded =
        ok && legacyEncoder != null ? legacyEncoder!(data) : data;
    final Map<String, dynamic> legacyBody = <String, dynamic>{
      'code': ok ? (legacySuccessCode ?? 0) : -1,
      'success': ok,
      if (ok) 'data': encoded else 'errorCode': code,
      if (!ok && message != null) 'message': message,
      if (legacyCallbackId != null) 'callbackId': legacyCallbackId,
    };
    final String json = jsonEncode(legacyBody);
    return '$callbackDispatcher(${jsonEncode(legacyCallbackId)}, $json);';
  }
}
