import 'origin.dart';
import 'tickets.dart';

enum NavigationPhase {
  idle,
  provisional,
  committed,
  finished,
  failed,
}

/// Platform-neutral navigation events.
///
/// Platform adapters must map iOS WKNavigationDelegate and Android
/// WebViewClient callbacks into these events. Security decisions should not be
/// attached directly to onPageStarted/onPageFinished because their timing and
/// redirect semantics differ.
sealed class NavigationEvent {
  const NavigationEvent(this.url, {this.isMainFrame = true});

  final String url;
  final bool isMainFrame;
}

class NavigationProvisionalStart extends NavigationEvent {
  const NavigationProvisionalStart(super.url, {super.isMainFrame});
}

class NavigationRedirected extends NavigationEvent {
  const NavigationRedirected(super.url, {super.isMainFrame});
}

class NavigationCommitted extends NavigationEvent {
  const NavigationCommitted(super.url, {super.isMainFrame});
}

class NavigationFinished extends NavigationEvent {
  const NavigationFinished(super.url, {super.isMainFrame});
}

class NavigationFailed extends NavigationEvent {
  const NavigationFailed(super.url, {super.isMainFrame});
}

class NavigationState {
  NavigationState(this.webViewId);

  final String webViewId;

  NavigationPhase phase = NavigationPhase.idle;
  int generation = 0;
  String? documentId;
  String? pendingUrl;
  BridgeOrigin? activeOrigin;
  DocumentTicket? activeTicket;
  List<String> redirectChain = <String>[];

  bool get hasActiveDocument =>
      (phase == NavigationPhase.committed ||
          phase == NavigationPhase.finished) &&
      activeOrigin != null &&
      activeTicket != null;

  /// Applies a normalized event and returns a newly issued ticket when a
  /// document becomes committed.
  DocumentTicket? apply(NavigationEvent event, TicketLedger tickets) {
    if (!event.isMainFrame) return activeTicket;

    return switch (event) {
      NavigationProvisionalStart() => _begin(event.url, tickets),
      NavigationRedirected() => _redirect(event.url),
      NavigationCommitted() => _commit(event.url, tickets),
      NavigationFinished() => _finish(event.url, tickets),
      NavigationFailed() => _fail(event.url, tickets),
    };
  }

  DocumentTicket? _begin(String url, TicketLedger tickets) {
    if (documentId != null) {
      tickets.revokeDocument(webViewId, documentId!);
    }
    generation += 1;
    documentId = '$webViewId#$generation';
    phase = NavigationPhase.provisional;
    pendingUrl = url;
    activeOrigin = null;
    activeTicket = null;
    redirectChain = <String>[url];
    return null;
  }

  DocumentTicket? _redirect(String url) {
    if (phase != NavigationPhase.provisional || documentId == null) {
      // Some platforms do not expose a distinct provisional start for every
      // redirect. Reconstruct the attempt instead of trusting a stale ticket.
      generation += 1;
      documentId = '$webViewId#$generation';
      redirectChain = <String>[];
    }

    phase = NavigationPhase.provisional;
    pendingUrl = url;
    redirectChain.add(url);
    activeOrigin = null;
    activeTicket = null;
    return null;
  }

  DocumentTicket? _commit(String url, TicketLedger tickets) {
    if (documentId == null || phase != NavigationPhase.provisional) {
      _begin(url, tickets);
    }

    final BridgeOrigin origin;
    try {
      origin = BridgeOrigin.parse(url);
    } on Object {
      phase = NavigationPhase.failed;
      pendingUrl = url;
      activeOrigin = null;
      activeTicket = null;
      if (documentId != null) {
        tickets.revokeDocument(webViewId, documentId!);
      }
      return null;
    }

    if (redirectChain.isEmpty || redirectChain.last != url) {
      redirectChain.add(url);
    }

    pendingUrl = url;
    activeOrigin = origin;
    phase = NavigationPhase.committed;

    final DocumentTicket ticket = tickets.issue(
      webViewId: webViewId,
      documentId: documentId!,
      origin: origin,
    );
    activeTicket = ticket;
    return ticket;
  }

  DocumentTicket? _finish(String url, TicketLedger tickets) {
    final BridgeOrigin? reportedOrigin = _tryOrigin(url);

    // Android/iOS can omit or reorder commit-like callbacks. onPageFinished is
    // late but safe: messages before a ticket exists are rejected.
    if (activeTicket == null ||
        activeOrigin == null ||
        (reportedOrigin != null && reportedOrigin != activeOrigin)) {
      final DocumentTicket? ticket = _commit(url, tickets);
      if (ticket == null) return null;
    }

    phase = NavigationPhase.finished;
    return activeTicket;
  }

  DocumentTicket? _fail(String url, TicketLedger tickets) {
    if (documentId != null) {
      tickets.revokeDocument(webViewId, documentId!);
    }
    phase = NavigationPhase.failed;
    pendingUrl = url;
    activeOrigin = null;
    activeTicket = null;
    return null;
  }

  static BridgeOrigin? _tryOrigin(String url) {
    try {
      return BridgeOrigin.parse(url);
    } on Object {
      return null;
    }
  }
}

class NavigationRegistry {
  final Map<String, NavigationState> _states = <String, NavigationState>{};

  NavigationState stateFor(String webViewId) {
    return _states.putIfAbsent(webViewId, () => NavigationState(webViewId));
  }

  DocumentTicket? handle(
    String webViewId,
    NavigationEvent event,
    TicketLedger tickets,
  ) {
    return stateFor(webViewId).apply(event, tickets);
  }

  void remove(String webViewId, TicketLedger tickets) {
    tickets.revokeWebView(webViewId);
    _states.remove(webViewId);
  }
}
