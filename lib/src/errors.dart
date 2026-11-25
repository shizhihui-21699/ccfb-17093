/// Stable, non-sensitive bridge error codes.
///
/// Do not put URLs, tokens, addresses, or stack traces in [BridgeException.publicMessage].
enum BridgeErrorCode {
  invalidMessage('INVALID_MESSAGE'),
  unauthenticated('UNAUTHENTICATED'),
  staleDocument('STALE_DOCUMENT'),
  originDenied('ORIGIN_DENIED'),
  frameDenied('FRAME_DENIED'),
  assuranceInsufficient('ASSURANCE_INSUFFICIENT'),
  unknownCapability('UNKNOWN_CAPABILITY'),
  invalidParams('INVALID_PARAMS'),
  rateLimited('RATE_LIMITED'),
  internal('INTERNAL');

  const BridgeErrorCode(this.wireName);

  final String wireName;
}

class BridgeException implements Exception {
  BridgeException(
    this.code, {
    this.developerMessage = '',
    this.cause,
  });

  final BridgeErrorCode code;
  final String developerMessage;
  final Object? cause;

  String get publicCode => code.wireName;

  @override
  String toString() => 'BridgeException(${code.wireName}, $developerMessage)';
}
