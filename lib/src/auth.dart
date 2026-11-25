import 'envelope.dart';
import 'errors.dart';
import 'source.dart';
import 'tickets.dart';
import 'transport.dart';

class BridgeAuthenticator {
  BridgeAuthenticator(this.tickets);

  final TicketLedger tickets;

  VerifiedSource authenticate(
    IncomingTransportMessage message,
    BridgeEnvelope envelope,
  ) {
    final TrustedFrameMetadata? metadata = message.frame;

    // Strong path: origin and isMainFrame come from native frame APIs, never
    // from the JSON body. Navigation event ordering cannot weaken this.
    if (metadata != null) {
      return VerifiedSource(
        webViewId: message.webViewId,
        origin: metadata.origin,
        frameKind: metadata.frameKind,
        assurance: SourceAssurance.nativeFrameMetadata,
        documentId: metadata.platformFrameId,
        platformFrameId: metadata.platformFrameId,
        ancestorChain: metadata.ancestorChain,
      );
    }

    // Compatibility path for the stock JavaScriptChannel. Possession of a
    // current ticket proves the call came from a context to which native code
    // delivered that ticket. It is only main-frame against cross-origin child
    // frames and must not unlock policies requiring nativeFrameMetadata.
    final String? token = envelope.ticket;
    if (token == null || token.isEmpty) {
      throw BridgeException(
        BridgeErrorCode.unauthenticated,
        developerMessage: 'No native frame metadata and no document ticket',
      );
    }

    final DocumentTicket? ticket =
        tickets.redeem(token, webViewId: message.webViewId);
    if (ticket == null) {
      throw BridgeException(
        BridgeErrorCode.staleDocument,
        developerMessage: 'Document ticket is unknown, expired, or rotated',
      );
    }

    return VerifiedSource(
      webViewId: message.webViewId,
      origin: ticket.origin,
      frameKind: FrameKind.mainFrame,
      assurance: SourceAssurance.documentTicket,
      documentId: ticket.documentId,
    );
  }
}
