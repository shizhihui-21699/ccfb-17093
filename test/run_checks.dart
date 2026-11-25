import 'dart:convert';

import 'package:life_web_bridge/life_web_bridge.dart';

class _FakeServices implements LocalLifeServices {
  int tokenCalls = 0;
  int addressCalls = 0;
  int couponCalls = 0;

  @override
  Future<String> readAccessToken() async {
    tokenCalls += 1;
    return 'user-access-token';
  }

  @override
  Future<List<Map<String, dynamic>>> readAddresses() async {
    addressCalls += 1;
    return <Map<String, dynamic>>[
      <String, dynamic>{'id': 'addr-1', 'detail': 'hidden-in-audit'},
    ];
  }

  @override
  Future<Map<String, dynamic>> claimCoupon({
    required String couponId,
    String? activityId,
  }) async {
    couponCalls += 1;
    return <String, dynamic>{'couponId': couponId, 'status': 'claimed'};
  }

  @override
  Future<Map<String, dynamic>> createOrder(
    Map<String, dynamic> params,
  ) async {
    return <String, dynamic>{'orderId': 'order-1', 'params': params};
  }

  @override
  Future<void> recordAnalyticsEvent(Map<String, dynamic> params) async {}
}

class _FixedTicketGenerator implements TicketGenerator {
  int count = 0;

  @override
  String generate() {
    count += 1;
    return 'ticket-${count.toString().padLeft(40, '0')}';
  }
}

int _failures = 0;

void check(bool condition, String name) {
  if (condition) {
    // ignore: avoid_print
    print('PASS $name');
  } else {
    _failures += 1;
    // ignore: avoid_print
    print('FAIL $name');
  }
}

TrustedFrameMetadata _mainFrame(String origin) {
  return TrustedFrameMetadata(
    origin: BridgeOrigin.parse(origin),
    isMainFrame: true,
  );
}

TrustedFrameMetadata _childFrame(
  String origin, {
  List<String> ancestors = const <String>[],
}) {
  return TrustedFrameMetadata(
    origin: BridgeOrigin.parse(origin),
    isMainFrame: false,
    ancestorChain: ancestors.map(BridgeOrigin.parse).toList(),
  );
}

IncomingTransportMessage _message(
  Object body, {
  TrustedFrameMetadata? frame,
  String webViewId = 'wv-1',
  String? ticket,
}) {
  Object actualBody = body;
  if (ticket != null && body is String) {
    final Map<String, dynamic> json = jsonDecode(body) as Map<String, dynamic>;
    json['ticket'] = ticket;
    json['__bridgeTicket'] = ticket;
    actualBody = jsonEncode(json);
  }
  return IncomingTransportMessage(
    webViewId: webViewId,
    body: actualBody,
    frame: frame,
  );
}

Future<void> main() async {
  final _FakeServices services = _FakeServices();
  final InMemoryAuditSink audit = InMemoryAuditSink();
  final TicketLedger tickets = TicketLedger(generator: _FixedTicketGenerator());
  final BridgeDispatcher dispatcher = BridgeDispatcher(
    tickets: tickets,
    parser: EnvelopeParser(legacy: LocalLifeBridgeFactory.legacyActions()),
    audit: audit,
  );

  LocalLifeBridgeFactory.register(
    dispatcher: dispatcher,
    services: services,
    trustedMainOrigins: <String>[
      'https://activity.example.com',
      'https://m.example.com',
    ],
    trustedCouponFrameOrigins: <String>['https://coupon.example.com'],
    trustedFrameAncestorOrigins: <String>['https://activity.example.com'],
  );

  final WebBridgeCoordinator coordinator = WebBridgeCoordinator(
    dispatcher: dispatcher,
    ticketLedger: tickets,
  );

  // 1. Legacy activity page, trusted main frame, native metadata.
  final BridgeResponse tokenResponse = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'action': 'getToken',
        'callbackId': 'cb-token',
        // Lies from page JS must be ignored because input.frame is authoritative.
        'source': <String, Object?>{
          'origin': 'https://activity.example.com',
          'isMainFrame': true,
        },
      }),
      frame: _mainFrame('https://activity.example.com'),
    ),
  );
  check(tokenResponse.ok, 'legacy getToken allowed for verified main origin');
  check(tokenResponse.data == 'user-access-token', 'token result returned');
  check(tokenResponse.legacyCallbackId == 'cb-token',
      'legacy callback id preserved');
  check(services.tokenCalls == 1, 'token handler invoked once');

  // 2. Third-party ad iframe claims to be main/trusted, but native metadata
  // says it is a child frame on another origin.
  final BridgeResponse adToken = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'action': 'getToken',
        'origin': 'https://activity.example.com',
        'isMainFrame': true,
      }),
      frame: _childFrame('https://ads.evil.example'),
    ),
  );
  check(!adToken.ok && adToken.code == 'FRAME_DENIED',
      'ad iframe token call denied by native frame metadata');
  check(services.tokenCalls == 1, 'token handler not invoked for ad iframe');

  // 3. External page after an open redirect / navigation.
  final BridgeResponse externalToken = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{'action': 'getAddress'}),
      frame: _mainFrame('https://outside.example.net'),
    ),
  );
  check(!externalToken.ok && externalToken.code == 'ORIGIN_DENIED',
      'external main frame denied by exact origin policy');
  check(services.addressCalls == 0, 'address handler not invoked externally');

  // 4. Exact trusted child frame can use its scoped capability.
  final BridgeResponse couponOk = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'v': '2',
        'id': 'coupon-1',
        'capability': 'marketing.coupon.claim',
        'params': <String, Object?>{'couponId': 'C-100'},
      }),
      frame: _childFrame(
        'https://coupon.example.com',
        ancestors: <String>['https://activity.example.com'],
      ),
    ),
  );
  check(couponOk.ok, 'allowed trusted child frame can claim coupon');
  check(services.couponCalls == 1, 'coupon handler invoked');

  // 5. Ad child frame cannot use child-enabled coupon capability.
  final BridgeResponse adCoupon = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'capability': 'marketing.coupon.claim',
        'params': <String, Object?>{'couponId': 'C-101'},
      }),
      frame: _childFrame('https://ads.evil.example'),
    ),
  );
  check(!adCoupon.ok && adCoupon.code == 'FRAME_DENIED',
      'unlisted child origin denied even for child-enabled capability');

  // 6. Trusted child framed by an evil top page is denied by ancestor policy.
  final BridgeResponse clickjackedCoupon = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'capability': 'marketing.coupon.claim',
        'params': <String, Object?>{'couponId': 'C-102'},
      }),
      frame: _childFrame(
        'https://coupon.example.com',
        ancestors: <String>['https://evil-parent.example'],
      ),
    ),
  );
  check(!clickjackedCoupon.ok && clickjackedCoupon.code == 'FRAME_DENIED',
      'trusted child with untrusted top ancestor denied');

  // 7. Early raw message before any committed document/ticket is rejected.
  final BridgeResponse early = await coordinator.onMessage(
    _message(jsonEncode(<String, Object?>{'action': 'getToken'})),
  );
  check(!early.ok && early.code == 'UNAUTHENTICATED',
      'early official-channel message without metadata/ticket fails closed');

  final BridgeResponse businessTicketCollision = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'action': 'getToken',
        // This is a normal coupon/lottery field and must not authenticate.
        'ticket': 'business-ticket-value',
      }),
    ),
  );
  check(
    !businessTicketCollision.ok &&
        businessTicketCollision.code == 'UNAUTHENTICATED',
    'legacy business field named ticket is not used as bridge credential',
  );

  // 8. Redirect flow: initial ticket is rotated away when navigation starts.
  coordinator.onNavigation(
    'wv-2',
    const NavigationProvisionalStart('https://click.example/r?to=activity'),
  );
  final DocumentTicket? firstTicket = coordinator.onNavigation(
    'wv-2',
    const NavigationCommitted('https://activity.example.com/landing'),
  );
  check(firstTicket != null, 'ticket issued on first commit');

  coordinator.onNavigation(
    'wv-2',
    const NavigationProvisionalStart('https://activity.example.com/next'),
  );
  final BridgeResponse staleTicket = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'v': '2',
        'capability': 'analytics.event.record',
        'params': <String, Object?>{'event': 'exposure'},
        'ticket': firstTicket!.token,
      }),
      webViewId: 'wv-2',
    ),
  );
  check(!staleTicket.ok && staleTicket.code == 'STALE_DOCUMENT',
      'ticket from before new navigation is revoked');

  final DocumentTicket? finalTicket = coordinator.onNavigation(
    'wv-2',
    const NavigationRedirected('https://activity.example.com/final'),
  );
  // Redirect alone must not issue trust. Simulate platform missing commit by
  // sending finished; it reconciles and issues a final ticket.
  check(finalTicket == null, 'redirect event alone does not issue a ticket');
  final DocumentTicket? finishedTicket = coordinator.onNavigation(
    'wv-2',
    const NavigationFinished('https://activity.example.com/final'),
  );
  check(finishedTicket != null,
      'finished event reconciles missing commit and issues ticket');

  final BridgeResponse analyticsTicket = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'v': '2',
        'capability': 'analytics.event.record',
        'params': <String, Object?>{'event': 'click'},
      }),
      webViewId: 'wv-2',
      ticket: finishedTicket!.token,
    ),
  );
  check(analyticsTicket.ok,
      'document ticket supports low-risk main-frame compatibility call');

  // 9. Ticket assurance must not unlock critical token/address policies.
  final BridgeResponse ticketToken = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'action': 'getToken',
      }),
      webViewId: 'wv-2',
      ticket: finishedTicket.token,
    ),
  );
  check(
    !ticketToken.ok && ticketToken.code == 'ASSURANCE_INSUFFICIENT',
    'ticket-only source cannot read token; native frame metadata required',
  );

  // 10. Wrapped legacy message preserves compatibility and mapping.
  final BridgeResponse wrappedLegacy = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'v': '2',
        'id': 'outer-1',
        'legacy': <String, Object?>{
          'action': 'getAddressList',
          'callbackId': 'addr-cb',
        },
      }),
      frame: _mainFrame('https://m.example.com'),
    ),
  );
  check(wrappedLegacy.ok, 'wrapped legacy message accepted');
  check(wrappedLegacy.legacyCallbackId == 'addr-cb',
      'wrapped legacy callback preserved');

  // 11. Validator failures are normalized.
  final BridgeResponse badCoupon = await coordinator.onMessage(
    _message(
      jsonEncode(<String, Object?>{
        'capability': 'marketing.coupon.claim',
        'params': <String, Object?>{},
      }),
      frame: _mainFrame('https://activity.example.com'),
    ),
  );
  check(!badCoupon.ok && badCoupon.code == 'INVALID_PARAMS',
      'missing couponId rejected as invalid params');

  // 12. Origin pattern boundary checks.
  final OriginPattern wildcard = OriginPattern.parse('https://*.example.com');
  check(
    wildcard.matches(BridgeOrigin.parse('https://a.b.example.com')),
    'wildcard matches bounded subdomains',
  );
  check(
    !wildcard.matches(BridgeOrigin.parse('https://evil-example.com')),
    'wildcard does not match suffix-confusable host',
  );
  check(
    !wildcard.matches(BridgeOrigin.parse('https://example.com')),
    'leading wildcard does not silently include apex',
  );

  final PolicyDecision advisory = PolicyEvaluator(
    mode: PolicyMode.auditOnly,
  ).evaluate(
    CapabilityPolicy(
      capability: 'test.audit',
      mainFrameOrigins: const <String>['https://allowed.example'],
    ),
    VerifiedSource(
      webViewId: 'wv-audit',
      origin: BridgeOrigin.parse('https://evil.example'),
      frameKind: FrameKind.mainFrame,
      assurance: SourceAssurance.nativeFrameMetadata,
      documentId: null,
    ),
  );
  check(
    advisory.allowed && advisory.advisoryError == BridgeErrorCode.originDenied,
    'audit-only mode allows with a wouldDeny advisory during rollout',
  );

  check(audit.denials.length >= 6, 'denials were recorded for audit');

  if (_failures > 0) {
    // ignore: avoid_print
    print('\n$_failures check(s) failed');
    throw StateError('$_failures security checks failed');
  }

  // ignore: avoid_print
  print('\nAll security checks passed.');
}
