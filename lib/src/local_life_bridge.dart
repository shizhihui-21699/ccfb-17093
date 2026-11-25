import 'dispatcher.dart';
import 'legacy.dart';
import 'policy.dart';
import 'source.dart';

/// Native business capabilities used by the local-life container.
class BridgeCapabilities {
  static const String accessTokenRead = 'identity.accessToken.read';
  static const String addressRead = 'profile.address.read';
  static const String couponClaim = 'marketing.coupon.claim';
  static const String orderCreate = 'trade.order.create';
  static const String analyticsEvent = 'analytics.event.record';
}

abstract class LocalLifeServices {
  Future<String> readAccessToken();

  Future<List<Map<String, dynamic>>> readAddresses();

  Future<Map<String, dynamic>> claimCoupon({
    required String couponId,
    String? activityId,
  });

  Future<Map<String, dynamic>> createOrder(Map<String, dynamic> params);

  Future<void> recordAnalyticsEvent(Map<String, dynamic> params);
}

class LocalLifeBridgeFactory {
  const LocalLifeBridgeFactory._();

  static LegacyActionRegistry legacyActions() {
    return LegacyActionRegistry(<LegacyActionMapping>[
      LegacyActionMapping(
        actions: <String>{'getToken', 'getUserToken', 'getLoginToken'},
        capability: BridgeCapabilities.accessTokenRead,
        encodeSuccess: (Object? result) {
          return <String, Object?>{
            'token': result,
            'accessToken': result,
          };
        },
      ),
      LegacyActionMapping(
        actions: <String>{'getAddress', 'getAddressList', 'queryAddress'},
        capability: BridgeCapabilities.addressRead,
        encodeSuccess: (Object? result) {
          return <String, Object?>{'addressList': result};
        },
      ),
      LegacyActionMapping(
        actions: <String>{'claimCoupon', 'receiveCoupon', 'lingquan'},
        capability: BridgeCapabilities.couponClaim,
        decodeParams: (Map<String, dynamic> raw) {
          final Object? nested = raw['params'] ?? raw['data'];
          final Map<String, dynamic> p =
              nested is Map ? Map<String, dynamic>.from(nested) : raw;
          return <String, dynamic>{
            'couponId': p['couponId'] ?? p['coupon_id'] ?? p['id'],
            'activityId': p['activityId'] ?? p['activity_id'],
          };
        },
        encodeSuccess: (Object? result) => result,
      ),
      const LegacyActionMapping(
        actions: <String>{'createOrder', 'submitOrder', 'xiadan'},
        capability: BridgeCapabilities.orderCreate,
      ),
      const LegacyActionMapping(
        actions: <String>{'track', 'reportEvent', 'sendLog'},
        capability: BridgeCapabilities.analyticsEvent,
      ),
    ]);
  }

  /// Registers least-privilege policies. Replace example origins with the
  /// exact production activity origins; do not use a global wildcard.
  static void register({
    required BridgeDispatcher dispatcher,
    required LocalLifeServices services,
    required Iterable<String> trustedMainOrigins,
    Iterable<String> trustedCouponFrameOrigins = const <String>[],
    Iterable<String> trustedFrameAncestorOrigins = const <String>[],
  }) {
    final Set<String> main = trustedMainOrigins.toSet();

    dispatcher.register(
      BridgeCapabilities.accessTokenRead,
      CapabilityPolicy(
        capability: BridgeCapabilities.accessTokenRead,
        mainFrameOrigins: main,
        // No child frame, including a same-origin child, receives the token
        // unless a future policy explicitly changes this.
        childFrameOrigins: const <String>[],
        minimumAssurance: SourceAssurance.nativeFrameMetadata,
        rateLimit: const RateLimit(maxCalls: 20, window: Duration(minutes: 1)),
      ),
      (_) async => services.readAccessToken(),
    );

    dispatcher.register(
      BridgeCapabilities.addressRead,
      CapabilityPolicy(
        capability: BridgeCapabilities.addressRead,
        mainFrameOrigins: main,
        childFrameOrigins: const <String>[],
        minimumAssurance: SourceAssurance.nativeFrameMetadata,
        rateLimit: const RateLimit(maxCalls: 10, window: Duration(minutes: 1)),
      ),
      (_) async => services.readAddresses(),
    );

    dispatcher.register(
      BridgeCapabilities.couponClaim,
      CapabilityPolicy(
        capability: BridgeCapabilities.couponClaim,
        mainFrameOrigins: main,
        // If coupon UI is genuinely embedded in a trusted child frame, list
        // its exact origin here. Ad/analytics frames stay absent and denied.
        childFrameOrigins: trustedCouponFrameOrigins,
        topLevelAncestorOrigins: trustedFrameAncestorOrigins,
        minimumAssurance: SourceAssurance.nativeFrameMetadata,
        rateLimit: const RateLimit(maxCalls: 30, window: Duration(minutes: 1)),
        validator: (Map<String, dynamic> params) {
          final Object? couponId = params['couponId'];
          if (couponId is! String || couponId.isEmpty) {
            throw ArgumentError('couponId is required');
          }
        },
      ),
      (BridgeRequestContext ctx) async {
        return services.claimCoupon(
          couponId: ctx.params['couponId'] as String,
          activityId: ctx.params['activityId'] as String?,
        );
      },
    );

    dispatcher.register(
      BridgeCapabilities.orderCreate,
      CapabilityPolicy(
        capability: BridgeCapabilities.orderCreate,
        mainFrameOrigins: main,
        childFrameOrigins: const <String>[],
        minimumAssurance: SourceAssurance.nativeFrameMetadata,
        rateLimit: const RateLimit(maxCalls: 10, window: Duration(minutes: 1)),
        validator: (Map<String, dynamic> params) {
          if (params['items'] is! List && params['skuId'] == null) {
            throw ArgumentError('items or skuId is required');
          }
        },
      ),
      (BridgeRequestContext ctx) => services.createOrder(ctx.params),
    );

    dispatcher.register(
      BridgeCapabilities.analyticsEvent,
      CapabilityPolicy(
        capability: BridgeCapabilities.analyticsEvent,
        mainFrameOrigins: main,
        // Third-party ad frames should normally use their own analytics
        // endpoint. If a non-sensitive first-party child needs this, add its
        // exact origin rather than wildcarding all frames.
        childFrameOrigins: trustedCouponFrameOrigins,
        minimumAssurance: SourceAssurance.documentTicket,
        rateLimit: const RateLimit(maxCalls: 120, window: Duration(minutes: 1)),
      ),
      (BridgeRequestContext ctx) async {
        await services.recordAnalyticsEvent(ctx.params);
        return const <String, bool>{'recorded': true};
      },
    );
  }
}
