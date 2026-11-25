package com.example.life_web_bridge

import android.net.Uri
import android.webkit.WebView
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewCompat
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject

/**
 * Source-aware Android bridge.
 *
 * WebMessageListener supplies the trustworthy `sourceOrigin` and
 * `isMainFrame` arguments. Do not replace these with fields from
 * `message.data`.
 *
 * Requires androidx.webkit:webkit >= 1.8.0.
 */
class SourceAwareBridge(
    webViewId: String,
    messenger: BinaryMessenger,
    private val allowedOriginRules: Set<String>,
) {
    private val channel = MethodChannel(
        messenger,
        "life_web_bridge/source_aware/$webViewId"
    )

    private var topLevelOrigin: String? = null

    fun attach(webView: WebView) {
        // These rules control which origins may reach the listener at all.
        // Dart CapabilityPolicy still performs per-capability authorization.
        WebViewCompat.addWebMessageListener(
            webView,
            "LifeSourceBridge",
            allowedOriginRules,
            sourceAwareListener
        )
    }

    fun trackTopLevelUrl(url: String?) {
        if (url == null) {
            topLevelOrigin = null
            return
        }

        val uri = Uri.parse(url)
        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase()
        if ((scheme != "https" && scheme != "http") || host == null) {
            topLevelOrigin = null
            return
        }

        val port = uri.port
        val isDefaultPort = port == -1 ||
            (scheme == "https" && port == 443) ||
            (scheme == "http" && port == 80)
        topLevelOrigin = if (isDefaultPort) {
            "$scheme://$host"
        } else {
            "$scheme://$host:$port"
        }
    }

    private val sourceAwareListener = object : WebViewCompat.WebMessageListener {
        override fun onPostMessage(
            view: WebView,
            message: WebMessageCompat,
            sourceOrigin: Uri,
            isMainFrame: Boolean,
            replyProxy: JavaScriptReplyProxy,
        ) {
            val source = mutableMapOf<String, Any?>(
                "origin" to sourceOrigin.toString(),
                "isMainFrame" to isMainFrame,
            )

            if (!isMainFrame && topLevelOrigin != null) {
                source["ancestors"] = listOf(topLevelOrigin)
            } else {
                source["ancestors"] = emptyList<String>()
            }

            val arguments = mapOf<String, Any?>(
                // The bootstrap sends a JSON string. Dictionaries are also fine.
                "body" to message.data,
                "source" to source,
            )

            channel.invokeMethod(
                "bridgeMessage",
                arguments,
                object : MethodChannel.Result {
                    override fun success(result: Any?) {
                        val responseJson = when (result) {
                            is String -> result
                            is Map<*, *> -> JSONObject(result).toString()
                            null -> """{"ok":false,"code":"INTERNAL"}"""
                            else -> JSONObject().put("data", result).toString()
                        }
                        replyProxy.postMessage(responseJson)
                    }

                    override fun error(
                        errorCode: String,
                        errorMessage: String?,
                        errorDetails: Any?,
                    ) {
                        replyProxy.postMessage(
                            JSONObject()
                                .put("ok", false)
                                .put("code", errorCode)
                                .toString()
                        )
                    }

                    override fun notImplemented() {
                        replyProxy.postMessage(
                            """{"ok":false,"code":"NOT_IMPLEMENTED"}"""
                        )
                    }
                }
            )
        }
    }
}
