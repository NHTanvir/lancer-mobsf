/*
 * lancer-mobsf Universal SSL Pinning Bypass
 * Bypasses common SSL pinning implementations:
 * - OkHttp3 CertificatePinner
 * - TrustManager (accept all certs)
 * - HttpsURLConnection hostname verifier
 * - Android TrustManagerImpl
 * - Flutter/Dart SSL
 */
Java.perform(function() {
    'use strict';

    // TrustManager - accept all certificates
    try {
        var TrustManager = Java.registerClass({
            name: 'com.lancer.TrustManager',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManagerArray = Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()]);
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
            .implementation = function(km, tm, sr) {
                this.init(km, TrustManagerArray, sr);
            };
        console.log('[lancer-ssl] TrustManager bypass installed');
    } catch(e) {
        console.log('[lancer-ssl] TrustManager bypass failed: ' + e.message);
    }

    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certs) {
            console.log('[lancer-ssl] OkHttp3 pin check bypassed for: ' + hostname);
        };
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, certs) {
            console.log('[lancer-ssl] OkHttp3 pin check bypassed for: ' + hostname);
        };
    } catch(e) {}

    // OkHttp3 CertificatePinner (builder pattern)
    try {
        var CertificatePinnerBuilder = Java.use('okhttp3.CertificatePinner$Builder');
        CertificatePinnerBuilder.build.implementation = function() {
            return Java.use('okhttp3.CertificatePinner').DEFAULT;
        };
    } catch(e) {}

    // HostnameVerifier - accept all hostnames
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HttpsURLConnection');
        HostnameVerifier.setDefaultHostnameVerifier.implementation = function() {};
        console.log('[lancer-ssl] HttpsURLConnection hostname verifier bypassed');
    } catch(e) {}

    // Android TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            return untrustedChain;
        };
    } catch(e) {}

    // WebView SSL errors
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
            console.log('[lancer-ssl] WebView SSL error bypassed');
        };
    } catch(e) {}

    console.log('[lancer-ssl] Universal SSL bypass complete');
});
