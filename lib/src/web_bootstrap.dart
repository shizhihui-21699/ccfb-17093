import 'dart:convert';

/// Document-start compatibility script.
///
/// It preserves old `SomeChannel.postMessage(jsonOrObject)` call sites by
/// wrapping those channel objects and forwarding a v2 envelope through the
/// source-aware outbound channel. It can also run in ticket-only mode on the
/// stock JavaScriptChannel.
///
/// The script never establishes trust by itself. Native/Dart must reject
/// messages without trustworthy frame metadata or a valid committed-document
/// ticket.
class WebBridgeBootstrap {
  const WebBridgeBootstrap._();

  static String build({
    required String outboundChannelName,
    List<String> wrapChannelNames = const <String>[],
    BridgeJavaScriptTransport transport =
        BridgeJavaScriptTransport.flutterGlobal,
    bool awaitDocumentTicket = false,
    List<String> helperGlobalNames = const <String>['LifeBridge'],
    String? legacyGlobalCallback,
  }) {
    final List<String> wrapped = wrapChannelNames.isEmpty
        ? <String>[outboundChannelName]
        : wrapChannelNames;
    final Map<String, Object?> config = <String, Object?>{
      'outboundName': outboundChannelName,
      'outboundKind': transport.wireName,
      'wrapChannelNames': wrapped,
      'awaitTicket': awaitDocumentTicket,
      'helperGlobalNames': helperGlobalNames,
      'legacyGlobalCallback': legacyGlobalCallback,
    };
    return kScript.replaceFirst(
      '/*__BRIDGE_CONFIG__*/ {}',
      '/*__BRIDGE_CONFIG__*/ ${jsonEncode(config)}',
    );
  }

  static const String kScript = r'''
(function () {
  'use strict';

  if (window.__lifeSecureBridgeInstalled === true) return;
  Object.defineProperty(window, '__lifeSecureBridgeInstalled', {
    value: true,
    writable: false,
    configurable: false
  });

  var CONFIG = /*__BRIDGE_CONFIG__*/ {};
  var outboundName = CONFIG.outboundName || 'LifeSourceBridge';
  var outboundKind = CONFIG.outboundKind || 'flutter-global';
  var wrapChannelNames = CONFIG.wrapChannelNames || [outboundName];
  var awaitTicket = CONFIG.awaitTicket === true;
  var ticket = null;
  var queue = [];
  var sequence = 0;
  var pending = Object.create(null);
  var legacyCallbacks = Object.create(null);
  var rawPosts = Object.create(null);

  function nowId() {
    sequence += 1;
    return 'lb-' + Date.now().toString(36) + '-' + sequence + '-' +
      Math.random().toString(36).slice(2, 10);
  }

  function parseMaybe(value) {
    if (typeof value !== 'string') return value;
    try { return JSON.parse(value); } catch (_) { return null; }
  }

  function getOutboundChannel() {
    if (outboundKind === 'webkit') {
      return window.webkit &&
        window.webkit.messageHandlers &&
        window.webkit.messageHandlers[outboundName];
    }
    return window[outboundName] || null;
  }

  function rawPost(envelope) {
    // If the outbound object is also a legacy object we wrapped, use the
    // saved native function. Calling channel.postMessage here would re-enter
    // wrappedPostMessage and loop forever.
    var savedRaw = rawPosts[outboundName];
    if (savedRaw) {
      savedRaw(JSON.stringify(envelope));
      return true;
    }

    var channel = getOutboundChannel();
    if (!channel || typeof channel.postMessage !== 'function') {
      return false;
    }
    channel.postMessage(JSON.stringify(envelope));
    return true;
  }

  function pumpQueue() {
    if (awaitTicket && !ticket) return;
    var jobs = queue;
    queue = [];
    for (var i = 0; i < jobs.length; i += 1) {
      if (ticket) jobs[i].ticket = ticket;
      if (!rawPost(jobs[i])) queue.push(jobs[i]);
    }
  }

  function sendEnvelope(envelope) {
    if (awaitTicket && !ticket) {
      queue.push(envelope);
      return envelope.id;
    }
    if (ticket) envelope.ticket = ticket;
    if (!rawPost(envelope)) queue.push(envelope);
    return envelope.id;
  }

  function request(capability, params, options) {
    options = options || {};
    var id = nowId();
    var envelope = {
      v: '2',
      id: id,
      capability: capability,
      params: params || {}
    };

    var promise = new Promise(function (resolve, reject) {
      pending[id] = { resolve: resolve, reject: reject };
      if (options.timeoutMs) {
        window.setTimeout(function () {
          if (!pending[id]) return;
          delete pending[id];
          reject(new Error('BRIDGE_TIMEOUT'));
        }, options.timeoutMs);
      }
    });

    sendEnvelope(envelope);
    return promise;
  }

  function deliverResponse(response) {
    if (!response || typeof response !== 'object') return;

    var id = response.requestId || response.id;
    var waiter = id ? pending[id] : null;
    if (waiter) {
      delete pending[id];
      if (response.ok) waiter.resolve(response.data);
      else waiter.reject(new Error(response.code || 'BRIDGE_DENIED'));
    }

    if (response.legacyCallbackId != null) {
      var cb = legacyCallbacks[response.legacyCallbackId];
      if (cb) {
        delete legacyCallbacks[response.legacyCallbackId];
        try { cb(response.ok ? response.data : response); } catch (_) {}
      }

      if (CONFIG.legacyGlobalCallback) {
        try {
          var parts = String(CONFIG.legacyGlobalCallback).split('.');
          var target = window;
          for (var i = 0; i < parts.length - 1; i += 1) {
            target = target[parts[i]];
          }
          if (target && typeof target[parts[parts.length - 1]] === 'function') {
            target[parts[parts.length - 1]](
              response.legacyCallbackId,
              response.ok ? response.data : response
            );
          }
        } catch (_) {}
      }
    }
  }

  // Native code calls this after a navigation has reached a verified commit in
  // stock-channel/ticket mode. Source-aware native transports do not need it.
  Object.defineProperty(window, '__lifeBridgeSetTicket', {
    value: function (nextTicket) {
      if (typeof nextTicket !== 'string' || nextTicket.length < 32) return;
      ticket = nextTicket;
      pumpQueue();
    },
    writable: false,
    configurable: false
  });

  Object.defineProperty(window, '__lifeBridgeReceive', {
    value: deliverResponse,
    writable: false,
    configurable: false
  });

  function wrapChannelPostMessage(name) {
    var channel = window[name];
    if (!channel || channel.__lifeBridgeWrapped === true) return true;

    var original = channel.postMessage;
    if (typeof original !== 'function') return false;
    rawPosts[name] = function (message) {
      return original.call(channel, message);
    };

    function wrappedPostMessage(message) {
      var legacy = parseMaybe(message);

      // Non-JSON legacy messages are preserved as bare actions. They fail
      // closed unless the native transport has trustworthy frame metadata.
      if (legacy === null || typeof legacy !== 'object') {
        var bareId = nowId();
        return sendEnvelope({
          v: '2',
          id: bareId,
          legacyChannel: name,
          legacy: { action: String(message) }
        });
      }

      var id = nowId();
      var envelope = {
        v: '2',
        id: id,
        legacyChannel: name,
        legacy: legacy
      };

      var callbackId = legacy.callbackId || legacy.callbackID || legacy.cbId;
      if (callbackId != null && typeof legacy.__lifeCallback === 'function') {
        legacyCallbacks[String(callbackId)] = legacy.__lifeCallback;
      }

      return sendEnvelope(envelope);
    }

    try {
      channel.postMessage = wrappedPostMessage;
    } catch (_) {
      try {
        Object.defineProperty(channel, 'postMessage', {
          value: wrappedPostMessage,
          writable: false,
          configurable: true
        });
      } catch (__) {
        // If the native property cannot be wrapped, the untouched legacy
        // message is still accepted only when native frame metadata is present.
        return false;
      }
    }

    try {
      Object.defineProperty(channel, '__lifeBridgeWrapped', {
        value: true,
        configurable: true
      });
    } catch (_) {}

    return true;
  }

  var attempts = 0;
  var timer = window.setInterval(function () {
    attempts += 1;
    var allWrapped = true;
    for (var i = 0; i < wrapChannelNames.length; i += 1) {
      if (!wrapChannelPostMessage(wrapChannelNames[i])) allWrapped = false;
    }
    pumpQueue();
    if (allWrapped || attempts > 200) window.clearInterval(timer);
  }, 5);

  var publicApi = {
    request: request,
    call: request,
    invoke: request,
    postMessage: function (capabilityOrMessage, params) {
      if (typeof capabilityOrMessage === 'string') {
        return request(capabilityOrMessage, params || {});
      }
      var id = nowId();
      sendEnvelope({ v: '2', id: id, legacy: capabilityOrMessage });
      return id;
    },
    _registerLegacyCallback: function (id, fn) {
      legacyCallbacks[String(id)] = fn;
    }
  };

  var names = CONFIG.helperGlobalNames || ['LifeBridge'];
  for (var n = 0; n < names.length; n += 1) {
    var helperName = names[n];
    if (!window[helperName]) {
      try {
        Object.defineProperty(window, helperName, {
          value: publicApi,
          writable: false,
          configurable: false
        });
      } catch (_) {
        window[helperName] = publicApi;
      }
    }
  }

  window.LifeSecureBridge = publicApi;
})();
''';
}

enum BridgeJavaScriptTransport {
  /// webview_flutter/Android-style `window.ChannelName.postMessage`.
  flutterGlobal('flutter-global'),

  /// iOS WKWebView `window.webkit.messageHandlers.Name.postMessage`.
  webkit('webkit');

  const BridgeJavaScriptTransport(this.wireName);

  final String wireName;
}
