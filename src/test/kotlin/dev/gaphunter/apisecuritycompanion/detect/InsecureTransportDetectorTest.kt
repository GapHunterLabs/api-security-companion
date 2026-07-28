package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class InsecureTransportDetectorTest {

    @Test
    fun flagsPlaintextHttpToRemoteHost() {
        val finding = InsecureTransportDetector.scanUrlLiteral("http://api.acme-corp.com/v1/orders")
        assertEquals("PLAINTEXT_HTTP", finding?.kind)
    }

    @Test
    fun ignoresHttpsUrls() {
        assertNull(InsecureTransportDetector.scanUrlLiteral("https://api.acme-corp.com/v1/orders"))
    }

    @Test
    fun ignoresLocalhost() {
        assertNull(InsecureTransportDetector.scanUrlLiteral("http://localhost:8080/health"))
        assertNull(InsecureTransportDetector.scanUrlLiteral("http://127.0.0.1:8080/health"))
    }

    @Test
    fun ignoresPrivateIpRanges() {
        assertNull(InsecureTransportDetector.scanUrlLiteral("http://10.0.1.5/internal"))
        assertNull(InsecureTransportDetector.scanUrlLiteral("http://192.168.1.5/internal"))
        assertNull(InsecureTransportDetector.scanUrlLiteral("http://172.16.0.5/internal"))
        assertNull(InsecureTransportDetector.scanUrlLiteral("http://172.31.255.255/internal"))
    }

    @Test
    fun doesNotTreat172DotSomethingOutsidePrivateRangeAsPrivate() {
        val finding = InsecureTransportDetector.scanUrlLiteral("http://172.32.0.5/external")
        assertEquals("PLAINTEXT_HTTP", finding?.kind)
    }

    @Test
    fun ignoresNonUrlStrings() {
        assertNull(InsecureTransportDetector.scanUrlLiteral("hello world"))
    }

    @Test
    fun flagsTrustAllCertificatesWhenNeitherMethodThrows() {
        val classText = """
            class InsecureTrustManager implements X509TrustManager {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        """.trimIndent()
        val finding = InsecureTransportDetector.scanTrustManagerBody(classText)
        assertEquals("TRUST_ALL_CERTIFICATES", finding?.kind)
    }

    @Test
    fun doesNotFlagARealTrustManagerThatThrows() {
        val classText = """
            class RealTrustManager implements X509TrustManager {
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    delegate.checkClientTrusted(chain, authType);
                    if (!valid) throw new CertificateException("invalid");
                }
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    delegate.checkServerTrusted(chain, authType);
                    if (!valid) throw new CertificateException("invalid");
                }
            }
        """.trimIndent()
        assertNull(InsecureTransportDetector.scanTrustManagerBody(classText))
    }

    @Test
    fun ignoresClassesThatDoNotImplementTrustManager() {
        val classText = """
            class OrderService {
                public void checkServerTrusted() {
                }
            }
        """.trimIndent()
        assertNull(InsecureTransportDetector.scanTrustManagerBody(classText))
    }
}
