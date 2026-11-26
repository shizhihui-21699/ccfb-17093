/// The page-side bootstrap, injected at **document start in every frame**.
///
/// This is the piece that lets dozens of already-shipped activity pages keep
/// working without being rewritten. Pages keep calling the same global
/// channel with the same legacy envelope; the bootstrap:
///
/// * assigns each document instance a random nonce (so native can bind a
///   grant to a *document*, not a URL),
/// * upgrades legacy calls into the modern token envelope on the way out,
/// * routes native replies back to the legacy callback ids the page expects,
/// * relays native challenges to descendant frames and reports each reply's
///   `event.origin` — the browser-set origin, which a frame cannot forge.
///
/// It holds no secrets: the token it is given is origin-scoped and only ever
/// readable from the document it was issued to.
library;

import 'dart:convert';

/// Builds the bootstrap source for a container using [channelName].
///
/// [channelName] is the JavaScript channel name registered with
/// `WebViewController.addJavaScriptChannel`. It is interpolated with
/// [jsonEncode] and again JSON-escaped inside the IIFE, so a channel name can
/// never break out of the script.
String buildBootstrapScript({required String channelName}) {
  final String ch = jsonEncode(channelName);
  return _template.replaceAll('__WB_CHANNEL_JSON__', ch);
}

/// Placeholder kept out of the way of Dart's `$` interpolation (the script is
/// full of `$`-free ES5, so no escaping is needed; this is a plain raw
/// string).
const String _template = r'''
(function () {
  'use strict';
  if (window.__wb) { return; }
  var CH = __WB_CHANNEL_JSON__;
  var MAX_DEPTH = 8;

  // --- random ids -------------------------------------------------------
  var HEX = '0123456789abcdef';
  function randomHex(bytes) {
    var out = '';
    try {
      var buf = new Uint8Array(bytes);
      (window.crypto || window.msCrypto).getRandomValues(buf);
      for (var i = 0; i < buf.length; i++) {
        out += HEX[(buf[i] >> 4) & 15] + HEX[buf[i] & 15];
      }
      return out;
    } catch (e) { /* fall through */ }
    for (var j = 0; j < bytes * 2; j++) {
      out += HEX[Math.floor(Math.random() * 16)];
    }
    return out;
  }

  var nonce = randomHex(16);

  // --- depth & child bookkeeping ----------------------------------------
  function ownDepth() {
    var d = 0, w = window;
    try {
      while (w.parent && w.parent !== w) {
        d++;
        if (d > MAX_DEPTH) { break; }
        w = w.parent;
      }
    } catch (e) { return MAX_DEPTH; } // cross-origin chain we cannot walk
    return d;
  }
  var depth = ownDepth();
  var isTop = depth === 0;

  // nonce -> window, for frames we have heard from (this frame's viewpoint).
  var kids = Object.create(null);
  // cid -> [{n, o, d}]
  var acks = Object.create(null);

  // --- transport --------------------------------------------------------
  var sent = 0;
  function sendRaw(s) {
    try {
      if (window[CH] && typeof window[CH].postMessage === 'function') {
        window[CH].postMessage(s);
        return true;
      }
    } catch (e) { /* ignore */ }
    try {
      var mh = window.webkit && window.webkit.messageHandlers;
      if (mh && mh[CH] && typeof mh[CH].postMessage === 'function') {
        mh[CH].postMessage(s);
        return true;
      }
    } catch (e) { /* ignore */ }
    return false;
  }

  function sendEnvelope(obj) {
    obj.v = 1;
    obj.t = token ? token.value : '';
    obj.f = token ? (token.frame || 'main') : 'main';
    try { sendRaw(JSON.stringify(obj)); } catch (e) { /* ignore */ }
    sent++;
  }

  // --- token ------------------------------------------------------------
  // Held in this closure only. Nothing about it is placed on a global that
  // page scripts can enumerate.
  var token = null;
  var caps = [];
  var grantedOrigin = null;

  function acceptsGrant(payload) {
    try {
      if (payload.o && payload.o !== location.origin) { return false; }
      if (payload.f === 'sub' && !isTop) {
        if (payload.n !== nonce) { return false; }
      }
      if (payload.f === 'main' && !isTop) { return false; }
      return true;
    } catch (e) { return false; }
  }

  // --- pending replies (id -> page callback) ----------------------------
  var pending = Object.create(null);
  var legacyReg = Object.create(null); // id -> true, for claim()
  var legacyCallback = Object.create(null); // id -> page callback id/function

  function newId() { return 'wb' + randomHex(8) + (sent.toString(16)); }

  function deliverToLegacy(id, ok, payload) {
    var cb = legacyCallback[id];
    delete legacyCallback[id];
    delete pending[id];
    if (cb === undefined) { return; }
    try {
      if (typeof cb === 'function') { cb(ok, payload); return; }
      var name = String(cb);
      var fn = window[name];
      if (typeof fn === 'function') { fn(ok, payload); }
    } catch (e) { /* ignore */ }
  }

  function deliverToModern(id, ok, payload) {
    var cb = pending[id];
    delete pending[id];
    if (typeof cb === 'function') {
      try { cb(ok, payload); } catch (e) { /* ignore */ }
    }
  }

  // --- child frame relay ------------------------------------------------
  function postDown(child, msg) {
    try { child.postMessage(msg, '*'); } catch (e) { /* ignore */ }
  }

  function childrenOf() {
    var out = [];
    try {
      for (var i = 0; i < window.frames.length; i++) {
        out.push(window.frames[i]);
      }
    } catch (e) { /* ignore */ }
    return out;
  }

  function startChallenge(cid) {
    var msg = { __wbC: cid };
    var kids_ = childrenOf();
    for (var i = 0; i < kids_.length; i++) { postDown(kids_[i], msg); }
    acks[cid] = acks[cid] || [];
    return acks[cid];
  }

  function relayAckUp(ack) {
    // Non-top frames pass acks to their parent with depth rebased by one, so
    // the top document ends up with a correctly labelled tree.
    try {
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({ __wbA: 1, c: ack.c, n: ack.n, d: ack.d + 1 }, '*');
      }
    } catch (e) { /* ignore */ }
  }

  function onMessage(e) {
    var d = e.data;
    if (!d || typeof d !== 'object') { return; }
    if (d.__wbC) {
      // A challenge from our parent: forward to our own kids, then answer
      // with our own identity. `e.origin` is filled by the browser on the
      // reply, so our parent never has to believe us.
      var cid = String(d.__wbC);
      startChallenge(cid);
      try {
        if (e.source && e.source !== window) {
          e.source.postMessage({ __wbA: 1, c: cid, n: nonce, d: depth }, '*');
        }
      } catch (err) { /* ignore */ }
      return;
    }
    if (d.__wbA) {
      var cid2 = String(d.c);
      var entry = { n: String(d.n), o: String(e.origin), d: Number(d.d) };
      if (typeof entry.d !== 'number' || entry.d < 1) { return; }
      if (!acks[cid2]) { acks[cid2] = []; }
      // Remember who to deliver to, for our own children.
      if (isTop) {
        kids[entry.n] = e.source;
        if (!acks[cid2].some(function (x) { return x.n === entry.n; })) {
          acks[cid2].push(entry);
        }
      } else {
        relayAckUp({ c: cid2, n: entry.n, d: entry.d });
        kids[entry.n] = e.source;
      }
      return;
    }
    if (d.__wbT && !isTop) {
      // A token destined for one of our descendants: hop it down.
      var target = kids[String(d.n)];
      if (target) { postDown(target, d); }
      return;
    }
    if (d.__wbT && isTop) {
      var t = kids[String(d.n)];
      if (t) { postDown(t, d); }
      return;
    }
    if (d.__wbG && !isTop) {
      if (acceptsGrant(d.__wbG)) {
        token = { value: d.__wbG.t, frame: 'sub' };
        caps = d.__wbG.caps || [];
        grantedOrigin = d.__wbG.o;
      }
      return;
    }
  }
  try { window.addEventListener('message', onMessage, false); } catch (e) { /* ignore */ }

  // --- native script entry points --------------------------------------
  var api = {
    nonce: nonce,
    depth: depth,
    isTop: isTop,

    // Synchronous read of the acks recorded for `cid` (native mints the cid,
    // so freshness is decided by native, not by the page).
    acks: function (cid) {
      if (!cid) { return []; }
      var list = acks[String(cid)] || [];
      return list.map(function (x) { return { n: x.n, o: x.o, d: x.d }; });
    },

    // Serve a pending legacy call to native, once. This is how a legacy page
    // proves *which document* produced a call that arrived through the
    // channel with no token.
    claim: function (id) {
      if (legacyReg[id]) {
        delete legacyReg[id];
        return true;
      }
      return false;
    },

    // Native → page: issue a grant.
    grant: function (id, payload) {
      try { payload = typeof payload === 'string' ? JSON.parse(payload) : payload; }
      catch (e) { return false; }
      if (!acceptsGrant(payload)) { return false; }
      if (payload.f === 'main' && isTop) {
        token = { value: payload.t, frame: 'main' };
        caps = payload.caps || [];
        grantedOrigin = payload.o;
        return true;
      }
      if (payload.f === 'sub') {
        if (kids[payload.n]) {
          postDown(kids[payload.n], { __wbT: 1, n: payload.n, __wbG: payload });
        }
        return true;
      }
      return false;
    },

    reply: function (payload) {
      try { payload = typeof payload === 'string' ? JSON.parse(payload) : payload; }
      catch (e) { return; }
      var id = payload && payload.id;
      if (!id) { return; }
      var ok = !payload.e;
      if (legacyCallback[id]) { deliverToLegacy(id, ok, ok ? payload.r : payload.e); return; }
      deliverToModern(id, ok, ok ? payload.r : payload.e);
    },

    // Explicit invoke from modern page code.
    invoke: function (cap, args, cb) {
      var id = newId();
      if (typeof cb === 'function') { pending[id] = cb; }
      sendEnvelope({ k: 'invoke', id: id, cap: cap, args: args || {} });
      return id;
    },

    onGrant: function (fn) { grantListeners.push(fn); },
    token: function () { return token ? token.value : null; },
    capabilities: function () { return caps.slice(); },
  };
  var grantListeners = [];
  try {
    Object.defineProperty(window, '__wb', {
      value: api, enumerable: false, configurable: false, writable: false,
    });
  } catch (e) { window.__wb = api; }

  // --- legacy shim ------------------------------------------------------
  // Old activity pages call `CHANNEL.postMessage(JSON.stringify({action:...}))`
  // directly. Rewrite those calls into the modern envelope *in flight*, so the
  // page needs no change and native sees full token attribution.
  var LEGACY_TO_CAP = {
    getToken: 'auth.token', getLoginToken: 'auth.token', 'auth.token': 'auth.token',
    getAddressList: 'address.list', getAddress: 'address.list',
    claimCoupon: 'coupon.claim', createOrder: 'order.create',
    closePage: 'ui.close', toast: 'ui.toast',
  };

  function looksLegacy(s) {
    if (typeof s !== 'string' || s.length > 4096) { return false; }
    return s.indexOf('"action"') !== -1 || s.indexOf('"action":') !== -1;
  }

  function rewriteLegacy(s) {
    var obj;
    try { obj = JSON.parse(s); } catch (e) { return null; }
    if (!obj || typeof obj.action !== 'string') { return null; }
    var cap = LEGACY_TO_CAP[obj.action];
    if (!cap) { return null; }
    var id = newId();
    legacyReg[id] = true;
    if (obj.callbackId !== undefined) { legacyCallback[id] = obj.callbackId; }
    else if (obj.cb) { legacyCallback[id] = obj.cb; }
    var args = obj.params || obj.args || {};
    sendEnvelope({ k: 'invoke', id: id, cap: cap, args: args });
    return true;
  }

  function wrapPostMessage(owner) {
    if (!owner || typeof owner.postMessage !== 'function') { return false; }
    var orig = owner.postMessage;
    try {
      Object.defineProperty(owner, 'postMessage', {
        configurable: true,
        writable: true,
        value: function (s) {
          if (looksLegacy(s)) {
            var done = rewriteLegacy(s);
            if (done) { return; }
          }
          return orig.apply(owner, arguments);
        },
      });
      return true;
    } catch (e) { return false; }
  }

  var shimmed = false;
  try {
    if (window[CH]) { shimmed = wrapPostMessage(window[CH]); }
    if (!shimmed) {
      var mh = window.webkit && window.webkit.messageHandlers;
      if (mh && mh[CH]) { shimmed = wrapPostMessage(mh[CH]); }
    }
  } catch (e) { /* ignore */ }
  api.shimmed = shimmed;

  // --- handshake --------------------------------------------------------
  var handshaking = false;
  var handshakeAttempts = 0;

  function handshake() {
    if (handshaking) { return; }
    if (token && (token.frame === 'main' || token.frame === depth === 1 ? 'sub' : 'sub')) {
      // Already have a token for this document; nothing to do.
      if (token) { return; }
    }
    handshaking = true;
    handshakeAttempts++;
    var id = newId();
    pending[id] = function () { handshaking = false; };
    sendEnvelope({ k: 'hello', id: id, args: { n: nonce, d: depth } });
    // Retry with backoff: the document may not yet satisfy native's ready
    // threshold, and native never grants early.
    if (handshakeAttempts < 6) {
      setTimeout(function () { handshaking = false; handshake(); }, 200 * handshakeAttempts);
    }
  }

  try {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', handshake, false);
    } else {
      handshake();
    }
    window.addEventListener('load', handshake, false);
    // SPA route changes and soft reloads keep the same document; re-handshake
    // defensively because native bumps the generation on every navigation
    // signal it sees.
    window.addEventListener('pageshow', function (e) {
      if (e && e.persisted) { handshake(); }
    }, false);
  } catch (e) { /* ignore */ }
})();
''';
