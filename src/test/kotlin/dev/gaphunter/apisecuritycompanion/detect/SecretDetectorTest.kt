package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class SecretDetectorTest {

    @Test
    fun detectsAwsAccessKey() {
        val finding = SecretDetector.scanLiteral("AKIAIOSFODNN7EXAMPLE")
        assertEquals("AWS_ACCESS_KEY", finding?.kind)
    }

    @Test
    fun detectsAwsAccessKeyEmbeddedInLongerString() {
        val finding = SecretDetector.scanLiteral("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")
        assertEquals("AWS_ACCESS_KEY", finding?.kind)
    }

    @Test
    fun detectsGithubToken() {
        val finding = SecretDetector.scanLiteral("ghp_" + "a".repeat(36))
        assertEquals("GITHUB_TOKEN", finding?.kind)
    }

    @Test
    fun detectsSlackToken() {
        // Built by concatenation, not a single literal -- GitHub's own push-protection
        // secret scanner flags the plain-literal form as a real Slack token, even in test code.
        val fakeToken = "xoxb-" + "1234567890-abcdefghijklmnop"
        val finding = SecretDetector.scanLiteral(fakeToken)
        assertEquals("SLACK_TOKEN", finding?.kind)
    }

    @Test
    fun detectsJwt() {
        val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzYXRlc3Q"
        val finding = SecretDetector.scanLiteral(jwt)
        assertEquals("JWT", finding?.kind)
    }

    @Test
    fun detectsStripeSecretKey() {
        // Built by concatenation, not a single literal -- same reason as
        // the Slack token test above: GitHub's own push-protection
        // secret scanner flags the plain-literal form as a real Stripe
        // key, even in test code.
        val fakeStripeKey = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        val finding = SecretDetector.scanLiteral(fakeStripeKey)
        assertEquals("STRIPE_KEY", finding?.kind)
    }

    @Test
    fun detectsStripeTestModeKeyToo() {
        val fakeStripeKey = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc"
        val finding = SecretDetector.scanLiteral(fakeStripeKey)
        assertEquals("STRIPE_KEY", finding?.kind)
    }

    @Test
    fun detectsStripeRestrictedKey() {
        val fakeStripeKey = "rk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        val finding = SecretDetector.scanLiteral(fakeStripeKey)
        assertEquals("STRIPE_KEY", finding?.kind)
    }

    @Test
    fun detectsPemPrivateKeyHeader() {
        val finding = SecretDetector.scanLiteral("-----BEGIN RSA PRIVATE KEY-----\nMIIB...")
        assertEquals("PRIVATE_KEY", finding?.kind)
    }

    @Test
    fun detectsGenericHighEntropySecretWithSuspiciousName() {
        val finding = SecretDetector.scanLiteral("Tt9!kQ2#mZp7@Lc4dW1&", variableNameHint = "apiSecret")
        assertEquals("GENERIC_HIGH_ENTROPY", finding?.kind)
    }

    @Test
    fun ignoresLowEntropyValueEvenWithSuspiciousName() {
        assertNull(SecretDetector.scanLiteral("aaaaaaaaaaaaaaaaaaaa", variableNameHint = "password"))
    }

    @Test
    fun ignoresObviousPlaceholderEvenWithSuspiciousName() {
        assertNull(SecretDetector.scanLiteral("changeme", variableNameHint = "password"))
        assertNull(SecretDetector.scanLiteral("your-api-key-here", variableNameHint = "apiKey"))
        assertNull(SecretDetector.scanLiteral("", variableNameHint = "secret"))
    }

    @Test
    fun ignoresHighEntropyValueWithoutSuspiciousVariableName() {
        assertNull(SecretDetector.scanLiteral("Tt9!kQ2#mZp7@Lc4dW1&", variableNameHint = "greeting"))
        assertNull(SecretDetector.scanLiteral("Tt9!kQ2#mZp7@Lc4dW1&", variableNameHint = null))
    }

    @Test
    fun ignoresOrdinaryStrings() {
        assertNull(SecretDetector.scanLiteral("Hello, world!"))
        assertNull(SecretDetector.scanLiteral("com.acmecorp.orders.OrderService"))
    }

    @Test
    fun entropyOfRepeatedCharacterIsZero() {
        assertEquals(0.0, SecretDetector.shannonEntropyBitsPerChar("aaaaaaaa"), 0.0001)
    }

    @Test
    fun entropyOfEmptyStringIsZero() {
        assertEquals(0.0, SecretDetector.shannonEntropyBitsPerChar(""), 0.0001)
    }

    @Test
    fun entropyOfHighlyVariedStringIsHigh() {
        val entropy = SecretDetector.shannonEntropyBitsPerChar("Tt9!kQ2#mZp7@Lc4dW1&")
        assertNotNull(entropy)
        assert(entropy > 3.5) { "expected high entropy, got $entropy" }
    }
}
