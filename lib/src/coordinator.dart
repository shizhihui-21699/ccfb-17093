import 'dispatcher.dart';
import 'navigation.dart';
import 'response.dart';
import 'tickets.dart';
import 'transport.dart';

/// Owns per-WebView navigation state, document tickets, dispatch, and replies.
class WebBridgeCoordinator {
  WebBridgeCoordinator({
    required this.dispatcher,
    TicketLedger? ticketLedger,
    NavigationRegistry? navigationRegistry,
    this.responseSink,
  })  : tickets = ticketLedger ?? TicketLedger(),
        navigation = navigationRegistry ?? NavigationRegistry();

  final BridgeDispatcher dispatcher;
  final TicketLedger tickets;
  final NavigationRegistry navigation;
  final BridgeResponseSink? responseSink;

  Future<BridgeResponse> onMessage(IncomingTransportMessage message) async {
    final BridgeResponse response = await dispatcher.dispatch(message);

    final BridgeResponseSink? sink = responseSink;
    if (sink != null) {
      await sink.send(
        response,
        webViewId: message.webViewId,
        replyToken: message.replyToken,
      );
    }
    return response;
  }

  /// Feed normalized platform navigation events here. The returned ticket, if
  /// any, should be delivered to the main frame by native/Dart evaluation.
  DocumentTicket? onNavigation(
    String webViewId,
    NavigationEvent event,
  ) {
    return navigation.handle(webViewId, event, tickets);
  }

  String? currentTicket(String webViewId) =>
      navigation.stateFor(webViewId).activeTicket?.token;

  void disposeWebView(String webViewId) {
    navigation.remove(webViewId, tickets);
  }
}
