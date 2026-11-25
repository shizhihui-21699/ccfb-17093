import 'dart:convert';
import 'dart:math';

import 'origin.dart';

abstract class TicketGenerator {
  String generate();
}

class SecureTicketGenerator implements TicketGenerator {
  SecureTicketGenerator([Random? random]) : _random = random ?? Random.secure();

  final Random _random;

  @override
  String generate() {
    final List<int> bytes = List<int>.generate(32, (_) => _random.nextInt(256));
    return base64Url.encode(bytes).replaceAll('=', '');
  }
}

class DocumentTicket {
  DocumentTicket({
    required this.token,
    required this.webViewId,
    required this.documentId,
    required this.origin,
    required this.issuedAt,
    this.ttl = const Duration(minutes: 30),
  });

  final String token;
  final String webViewId;
  final String documentId;
  final BridgeOrigin origin;
  final DateTime issuedAt;
  final Duration ttl;

  bool isExpiredAt(DateTime now) => now.difference(issuedAt) > ttl;
}

/// Stores active document tickets. Tokens are bearer secrets and must only be
/// delivered by native code to the verified main frame.
class TicketLedger {
  TicketLedger({TicketGenerator? generator, this.clock})
      : generator = generator ?? SecureTicketGenerator();

  final TicketGenerator generator;
  final DateTime Function()? clock;
  final Map<String, DocumentTicket> _tickets = <String, DocumentTicket>{};

  DateTime _now() => clock?.call() ?? DateTime.now();

  DocumentTicket issue({
    required String webViewId,
    required String documentId,
    required BridgeOrigin origin,
    Duration ttl = const Duration(minutes: 30),
  }) {
    final DocumentTicket ticket = DocumentTicket(
      token: generator.generate(),
      webViewId: webViewId,
      documentId: documentId,
      origin: origin,
      issuedAt: _now(),
      ttl: ttl,
    );
    _tickets[ticket.token] = ticket;
    return ticket;
  }

  DocumentTicket? redeem(
    String? token, {
    required String webViewId,
  }) {
    if (token == null || token.length < 32) return null;

    final DocumentTicket? ticket = _tickets[token];
    if (ticket == null) return null;
    if (ticket.webViewId != webViewId) return null;
    if (ticket.isExpiredAt(_now())) {
      _tickets.remove(token);
      return null;
    }
    return ticket;
  }

  void revokeDocument(String webViewId, String documentId) {
    _tickets.removeWhere(
      (_, DocumentTicket t) =>
          t.webViewId == webViewId && t.documentId == documentId,
    );
  }

  void revokeWebView(String webViewId) {
    _tickets.removeWhere((_, DocumentTicket t) => t.webViewId == webViewId);
  }
}
