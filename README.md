# 来源与子框架可判定的 Web → Native 安全桥

这个目录给出一套可运行的纯 Dart 核心实现，以及 Flutter / iOS / Android 接入样例。目标不是再注册一个“通用通道”，而是把网页调用原生能力改成一条**带来源认证、框架认证、能力级授权和审计**的调用链。

```text
旧活动页 JS
   │  旧 Action / 旧 channel.postMessage(json)
   ▼
文档启动时注入的兼容垫片（自动包 v2 envelope、排队、带 ticket）
   │
   ├── 推荐：SourceAwareBridge
   │      iOS WKScriptMessage.frameInfo
   │      Android WebMessageListener(sourceOrigin, isMainFrame)
   │      └── MethodChannel ──► Dart TrustedFrameMetadata
   │
   └── 兜底：webview_flutter JavaScriptChannel
          └── 无来源、无 frame；只能依赖提交后轮换的 document ticket
                 └── ticket 仅代表“主框架上下文持有密钥”，
                     不能区分同源子框架/同源恶意脚本
                                      │
                                      ▼
                         EnvelopeParser / Legacy 映射
                                      │
                                      ▼
                         BridgeAuthenticator（只信原生元数据/ticket）
                                      │
                                      ▼
                         CapabilityPolicy（能力 × origin × frame）
                                      │
                                      ▼
                         参数校验 / 频控 / Handler / 审计
```

运行核心安全用例：

```bash
dart pub get
dart test
# 或直接查看逐条断言：
dart run test/run_checks.dart
```

## 1. 必须先承认的平台边界

官方 `webview_flutter` 的回调大致只有：

```dart
addJavaScriptChannel(
  'LifeBridge',
  onMessageReceived: (JavaScriptMessage message) {
    // message.message 只有字符串；没有可信 origin，也没有 isMainFrame。
  },
);
```

因此下面这些做法都不能作为安全依据：

- 让 H5 在消息体里传 `origin`、`sourceOrigin`、`isMainFrame`、`frameId`；
- 用当前 `WebViewController.currentUrl()` 和消息时间做“大致匹配”；
- 只在 JS 里判断 `window.top === window`；
- 用 URL 字符串包含 `activity.example.com` 做校验。

这些字段都由页面控制，广告 iframe、外部跳转页或抢先注入脚本都可以伪造成“主框架 + 官方域名”。

关键能力（登录 token、收货地址、下单）必须使用平台提供的可信 frame 元数据：

- iOS：`WKScriptMessage.frameInfo.securityOrigin` 和 `frameInfo.isMainFrame`；
- Android：`WebViewCompat.WebMessageListener.onPostMessage(... sourceOrigin, isMainFrame, replyProxy)`。

样例：

- `platform/ios/SourceAwareBridge.swift`
- `platform/android/SourceAwareBridge.kt`
- `integration/flutter/source_aware_method_bridge.dart`

如果短期只能使用官方 `JavaScriptChannel`，本方案提供导航绑定的一次性/轮换 ticket。ticket 能挡住：

如果可以引入其他 WebView 插件，也应优先选择能在 Dart 回调中直接给出 `sourceOrigin/isMainFrame` 的 `WebMessageListener` 兼容实现（例如 `flutter_inappwebview` 的对应 API），但仍要确认其元数据来自原生回调而不是 JS 消息体。

它能挡住：

- 提交前抢先发送的裸消息；
- 跨源 iframe（读不到主框架 ticket）；
- 重定向前旧文档持有的 ticket；
- 普通外部页面直接调用通道。

但它**不能**区分同源子框架，也不能防住已经在可信主源内执行的恶意/被污染脚本。因此策略里把 `identity.accessToken.read`、`profile.address.read`、`trade.order.create` 配置成必须达到 `SourceAssurance.nativeFrameMetadata`；ticket-only 调用只会得到 `ASSURANCE_INSUFFICIENT`。

## 2. 每个能力独立授权，而不是一个通用 invoke

能力名稳定、显式注册，不允许把 JS 字符串映射成任意 Dart 方法或反射调用：

```dart
dispatcher.register(
  'identity.accessToken.read',
  CapabilityPolicy(
    capability: 'identity.accessToken.read',
    mainFrameOrigins: const <String>[
      'https://activity.example.com',
      'https://m.example.com',
    ],
    childFrameOrigins: const <String>[],
    minimumAssurance: SourceAssurance.nativeFrameMetadata,
    rateLimit: const RateLimit(maxCalls: 20, window: Duration(minutes: 1)),
  ),
  (ctx) => sessionStore.accessToken,
);
```

策略矩阵建议：

| 能力 | 主框架来源 | 子框架 | 最低认证强度 |
|---|---|---|---|
| `identity.accessToken.read` | 登录/活动主域精确 origin | 一律拒绝 | 原生 frame 元数据 |
| `profile.address.read` | 交易/活动主域精确 origin | 一律拒绝 | 原生 frame 元数据 |
| `trade.order.create` | 交易主域 | 一律拒绝 | 原生 frame 元数据 + 参数校验/频控 |
| `marketing.coupon.claim` | 活动主域 | 仅列名的券 iframe origin，可校验顶层祖先 | 原生 frame 元数据 |
| `analytics.event.record` | 主域 | 可按需要列名 | ticket 或原生元数据 |

默认拒绝：能力没有注册、origin 不匹配、frame 不允许、认证强度不足、参数校验失败或超频，都不会进入 handler。

Origin 使用 scheme + host + canonical port 比较，不使用子串。`https://*.example.com` 是有边界的通配规则：匹配 `a.example.com` / `a.b.example.com`，不匹配 `evil-example.com`，也不自动包含裸 `example.com`。生产建议尽量全部配精确 origin。

## 3. 主框架 / 子框架如何判定

推荐链路中，Dart 的 `TrustedFrameMetadata` 只允许由原生适配器构造：

```dart
final frame = TrustedFrameMetadata(
  origin: BridgeOrigin.parse(source['origin'] as String),
  isMainFrame: source['isMainFrame'] == true,
  ancestorChain: ancestors,
);
```

随后生成 `VerifiedSource`：

- `frameKind == mainFrame`：按主框架 origin 授权；
- `frameKind == childFrame`：必须命中该能力自己的 `childFrameOrigins`；
- 元数据缺失且 ticket 无效：`FrameKind.unknown`，默认拒绝。

对于“可信券 iframe 被恶意父页面嵌套”的点击劫持风险，可以配置 `topLevelAncestorOrigins`。Android/iOS 回调本身通常不直接给完整祖先链；样例由原生导航状态记录顶层 origin，并作为 `ancestors: [topLevelOrigin]` 传给 Dart。需要完整祖先链时，应在原生侧进一步维护 frame 树，不能直接信任 JS 的 `location.ancestorOrigins`。

## 4. 多次重定向和双端时序不一致

不要把安全状态直接绑死在某一个平台事件名上。核心状态机在 `lib/src/navigation.dart`，把双端事件归一化为：

```text
ProvisionalStart → Redirected* → Committed → Finished
                                  └────────→ Failed
```

规则：

1. 每次新的 provisional navigation 增加 generation，并立即吊销上一文档 ticket；
2. redirect 只更新候选 URL/重定向链，不发放信任；
3. 只有 commit，或在缺失 commit 事件时由 finish 做保守对账，才按最终 origin 签发新 ticket；
4. `onPageStarted` 不等同于可信提交；
5. `onPageFinished` 较晚但安全，早到的消息直接拒绝，兼容垫片会排队；
6. 主框架失败才吊销主 ticket；子资源加载错误不应影响当前主文档。

推荐的 source-aware 链路甚至不依赖导航时序做授权：每条消息都带 WebKit/Android 当场给出的 `sourceOrigin + isMainFrame`。导航状态主要用于 ticket 兜底、注入和审计对账。

## 5. 恶意页面抢发消息

安全设计是 fail-closed：

- 没有原生 frame 元数据，也没有当前文档 ticket：`UNAUTHENTICATED`；
- ticket 是旧 generation、不存在、过期或 webViewId 不匹配：`STALE_DOCUMENT`；
- origin 不在该能力白名单：`ORIGIN_DENIED`；
- 子框架不允许该能力：`FRAME_DENIED`；
- ticket 强度不足以读取 token/地址：`ASSURANCE_INSUFFICIENT`。

因此，恶意页面即使在合法页面加载完成前抢到 JS 执行权，也只能产生审计中的拒绝记录，不能进入原生 handler。

需要注意：如果恶意脚本已经在**可信主源内部**执行（例如主站直接引入了被入侵的第三方广告脚本，且它和主页面同源），origin 和 isMainFrame 都无法区分“第一方代码”和“同源第三方脚本”。这不是桥协议能单独解决的问题。应同时：

- 把广告/活动第三方内容放进独立 cross-origin iframe，并在桥策略中拒绝其子框架敏感能力；
- 使用 CSP、SRI、脚本域名隔离；
- 敏感操作加原生确认、用户手势、短期授权；
- 不下发长期 refresh token，access token 也应短期、可吊销。

## 6. 几十个已上线活动页如何兼容

不需要重写页面。兼容分三层：

### 6.1 旧 Action 映射

在 `LegacyActionRegistry` 中集中把旧协议映射到稳定能力：

```dart
LegacyActionMapping(
  actions: {'getToken', 'getUserToken', 'getLoginToken'},
  capability: BridgeCapabilities.accessTokenRead,
  encodeSuccess: (result) => {'token': result, 'accessToken': result},
);
```

已内置示例：

- `getToken/getUserToken/getLoginToken`
- `getAddress/getAddressList/queryAddress`
- `claimCoupon/receiveCoupon`
- `createOrder/submitOrder`
- `track/reportEvent/sendLog`

未知 action 仍然拒绝，不能因为“兼容”开放通用调用。

### 6.2 文档启动注入垫片

`WebBridgeBootstrap.build(...)` 生成一段原生 document-start user script，自动：

- 包装旧的 `LifeBridge.postMessage(json)`；
- 转成 `{v:'2', id, legacy: <旧消息>}`；
- 保留旧 `callbackId`；
- ticket 未到位时排队，到位后 flush；
- 提供 `window.LifeBridge.request(capability, params)` 给新页面；
- 接收 `window.__lifeBridgeReceive(response)`。

iOS 应通过 `WKUserScriptInjectionTime.atDocumentStart` 注入；Android 使用 `WebViewCompat.addDocumentStartJavaScript(...)`。只在 `onPageStarted/onPageFinished` 里 `runJavaScript` 可能太晚，只能作为兜底。

### 6.3 原生元数据直连

推荐让垫片把 envelope 发到新的 `LifeSourceBridge`：

- Android：`window.LifeSourceBridge.postMessage(...)`
- iOS：`window.webkit.messageHandlers.LifeSourceBridge.postMessage(...)`

旧页面仍调用旧 channel 名，垫片包装后转发到新 source-aware channel。原生侧从 frame API 取来源，再通过 `life_web_bridge/source_aware/<webViewId>` MethodChannel 调 Dart。

注入垫片时按平台选择 JS 寻址方式：

```dart
// Android / WebMessageListener 风格：window.LifeSourceBridge.postMessage
final androidBootstrap = WebBridgeBootstrap.build(
  outboundChannelName: 'LifeSourceBridge',
  wrapChannelNames: const <String>['LifeBridge'],
  transport: BridgeJavaScriptTransport.flutterGlobal,
);

// iOS WKScriptMessageHandler 风格：
// window.webkit.messageHandlers.LifeSourceBridge.postMessage
final iosBootstrap = WebBridgeBootstrap.build(
  outboundChannelName: 'LifeSourceBridge',
  wrapChannelNames: const <String>['LifeBridge'],
  transport: BridgeJavaScriptTransport.webkit,
);
```

如果包装失败或攻击者找到未被替换的原生 `postMessage` 原始函数：

- source-aware 通道仍有原生元数据，按真实 frame 拒绝；
- 官方 channel 兜底模式下，裸旧消息没有有效 ticket，仍然拒绝。

## 7. 登录 token 和地址的数据面收敛

授权通过后，也建议减少暴露：

- `accessToken.read` 只允许主框架精确 origin，返回短期 token；更好的方式是原生代发带 Authorization 的请求，JS 根本不接触 token；
- 地址按业务最小字段返回，避免整表/手机号/门牌号全量下发；
- 券、订单参数做 schema 校验、频控和幂等；
- 审计只记录 webViewId、origin、frame、capability、决策、原因、requestId，不记录消息参数、token、地址；
- 原生日志同样要对 raw body 脱敏，因为旧协议可能把 PII 放在 JSON 里。

## 8. 建议上线顺序

1. **盘点**：列出全部活动域名、跳转/开放重定向域名、iframe/广告域名、旧 action 和 channel 名。
2. **观测**：可临时使用 `PolicyEvaluator(mode: PolicyMode.auditOnly)`，把本应拒绝的调用记为 `wouldDeny` 但放行，确认白名单遗漏；盘点结束后必须切回 `PolicyMode.enforce`。
3. **原生元数据**：接入 iOS/Android source-aware listener，Dart 侧同时保留旧 channel。
4. **灰度拦截**：先拦截 token、地址、下单的 child frame 和未知 origin；再切 exact origin。
5. **注入垫片**：document-start 注入，保留旧 action/callback 协议。
6. **ticket 兜底**：导航状态机上线，逐步缩短 ticket TTL；关键能力仍要求强元数据。
7. **收敛第三方脚本**：广告迁移到 cross-origin sandbox iframe，配置 CSP/SRI。
8. **全量拒绝默认策略**：未注册能力、未知来源、未知 frame 全部 deny，并保留安全告警。

## 9. 目录说明

```text
lib/src/origin.dart              Origin 规范化与有界通配匹配
lib/src/source.dart              可信 frame 元数据 / 认证后的来源
lib/src/tickets.dart             安全随机 document ticket 与台账
lib/src/navigation.dart          双端导航事件归一化状态机
lib/src/envelope.dart            v2 envelope 与旧协议解析
lib/src/legacy.dart              旧 action → 新能力映射
lib/src/policy.dart              能力级 origin/frame/强度/频控策略
lib/src/auth.dart                原生元数据优先、ticket 兜底认证
lib/src/dispatcher.dart          解析→认证→授权→校验→Handler→审计
lib/src/coordinator.dart         WebView 导航/ticket/消息/响应总协调
lib/src/web_bootstrap.dart       向后兼容 JS 垫片
lib/src/local_life_bridge.dart   本地生活能力和策略示例
test/run_checks.dart             28 个攻防/兼容性断言
integration/flutter/             webview_flutter 与 MethodChannel 接入样例
platform/ios/                    WKFrameInfo 元数据样例
platform/android/                WebMessageListener 元数据样例
```

## 参考资料

- [webview_flutter `JavaScriptMessage` API](https://pub.dev/documentation/webview_flutter/latest/webview_flutter/JavaScriptMessage-class.html)
- [Apple: `WKScriptMessage.frameInfo`](https://developer.apple.com/documentation/webkit/wkscriptmessage/frameinfo)
- [Apple: `WKFrameInfo`](https://developer.apple.com/documentation/webkit/wkframeinfo)
- [AndroidX WebKit: `WebViewCompat.WebMessageListener`](https://developer.android.com/reference/androidx/webkit/WebViewCompat.WebMessageListener)
- [MDN: `Window.postMessage`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
