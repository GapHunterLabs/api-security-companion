package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The rules brought in line with secret-scanner-cli 0.3.0: key names with suffixes
 * in every naming convention, a byte-order mark in front of a `.env`, redacted
 * placeholders, and ten more exact formats. Every fake token is built from pieces.
 */
class SecretRulesParityTest {

    private companion object {
        const val ALNUM = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uVwXyZ"
        const val HEX = "0123456789abcdef"
        const val ENTROPY = "Tt9!kQ2#mZp7@Lc4dW1&"
        fun mixed(n: Int, alphabet: String) = (0 until n).map { alphabet[(it * 7 + 3) % alphabet.length] }.joinToString("")
        val GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    }

    private fun kind(v: String) = SecretDetector.scanSignatures(v)?.kind

    // ---- key names: suffixes and conventions ----

    @Test
    fun wordsSplitTheSameWayInEveryConvention() {
        for (k in listOf("clientSecret", "ClientSecret", "client-secret", "client_secret", "CLIENT_SECRET", "client.secret")) {
            assertEquals(k, listOf("client", "secret"), KeyName.words(k))
        }
        assertEquals(listOf("api", "key"), KeyName.words("APIKey"))
        assertEquals(listOf("api", "key", "v", "2"), KeyName.words("apiKeyV2"))
        assertEquals(emptyList<String>(), KeyName.words("__"))
    }

    @Test
    fun suffixedCredentialKeysAreRecognized() {
        for (k in listOf("API_KEY_1", "DB_PASSWORD_PROD", "AUTH_TOKEN_V2", "apiKeyProd", "clientSecretStaging", "client-secret-dev",
            "SECRET_KEY_PRIMARY", "token.secondary", "ApiKeyV10", "password1", "TOKEN_QA")) {
            assertTrue(k, ConfigSecretScanner.isCredentialKey(k))
        }
    }

    @Test
    fun keysAboutACredentialStayUnreportedWithSuffixes() {
        for (k in listOf("token_url", "TOKEN_URL_PROD", "secretNameV2", "password_policy_1", "CACHE_KEY_PROD", "KEY_1", "PROD", "V2", "")) {
            assertFalse("'$k'", ConfigSecretScanner.isCredentialKey(k))
        }
        assertEquals(listOf("prod"), KeyName.core("PROD"))
        assertEquals(listOf("api", "key"), KeyName.core("API_KEY_V2_PROD"))
    }

    @Test
    fun suffixedKeysAreReportedInADotEnvWhenTheHeuristicIsOn() {
        val text = "API_KEY_1=$ENTROPY\nDB_PASSWORD_PROD=$ENTROPY\nTOKEN_URL_PROD=$ENTROPY\n"
        assertEquals(2, ConfigSecretScanner.scanDotEnv(text, heuristicEnabled = true).size)
        assertTrue(ConfigSecretScanner.scanDotEnv(text, heuristicEnabled = false).isEmpty())
    }

    // ---- byte-order mark ----

    @Test
    fun aByteOrderMarkNoLongerHidesLineOneOfADotEnvAndOffsetsStayExact() {
        val text = "\uFEFFGH_TOKEN=$GITHUB\nOTHER=$GITHUB\n"
        val hits = ConfigSecretScanner.scanDotEnv(text, heuristicEnabled = false)
        assertEquals(2, hits.size)
        for (hit in hits) assertEquals(GITHUB, text.substring(hit.start, hit.end))
        assertEquals("only line 1 can carry a mark", 0, ConfigSecretScanner.scanDotEnv("A=1\n\uFEFFGH=$GITHUB\n", false).size)
    }

    // ---- placeholders ----

    @Test
    fun redactedBodiesAndTheAwsExampleKeyAreNotReported() {
        assertNull(kind("ghp_" + "X".repeat(36)))
        assertNull(kind("sk_live_" + "X".repeat(24)))
        assertNull(kind("AKIA" + "X".repeat(16)))
        assertNull(kind("sk-proj-" + "X".repeat(48)))
        assertNull(kind("AKIA" + "IOSFODNN7EXAMPLE"))
        assertEquals("GITHUB_TOKEN", kind("ghp_" + "X".repeat(30) + "a1B2c3"))
        assertEquals("a real token after a placeholder on the same line is still found", "GITHUB_TOKEN", kind("ghp_" + "X".repeat(36) + " then $GITHUB"))
        assertFalse(SecretDetector.looksLikeARealSecret("REPLACE_ME"))
        assertFalse(SecretDetector.looksLikeARealSecret("replace-me"))
    }

    // ---- ten more exact formats ----

    @Test
    fun everyNewFormatMatchesAtItsShortestAndNotOneCharacterLess() {
        fun pair(prefix: String, body: String, suffix: String = "") = (prefix + body + suffix) to (prefix + body.dropLast(1) + suffix)
        val cases = mapOf(
            "ATLASSIAN_API_TOKEN" to pair("ATATT3", mixed(186, ALNUM + "_-=")),
            "DOPPLER_TOKEN" to pair("dp.pt.", mixed(43, ALNUM)),
            "AGE_SECRET_KEY" to pair("AGE-SECRET-KEY-1", mixed(58, "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L")),
            "LINEAR_API_KEY" to pair("lin_api_", mixed(40, ALNUM)),
            "POSTMAN_API_KEY" to pair("PMAK-" + mixed(24, HEX) + "-", mixed(34, HEX)),
            "GRAFANA_SERVICE_ACCOUNT_TOKEN" to pair("glsa_" + mixed(32, ALNUM) + "_", mixed(8, HEX)),
            "SQUARE_ACCESS_TOKEN" to pair("sq0atp-", mixed(22, ALNUM)),
            "AZURE_STORAGE_KEY" to pair("AccountKey=", mixed(86, ALNUM + "+/"), "=="),
            "BCRYPT_HASH" to pair("$" + "2b$12$", mixed(53, "./" + ALNUM)),
        )
        for ((k, p) in cases) {
            assertEquals("$k shortest", k, kind(p.first))
            assertEquals("$k inside a line", k, kind("x = '${p.first}' # note"))
            assertTrue("$k one shorter", kind(p.second) != k)
            assertFalse("$k description never echoes the value", SecretDetector.scanSignatures(p.first)!!.description.contains(p.first))
        }
        assertEquals(32, SecretDetector.SIGNATURE_KINDS.size)
        assertEquals(SecretDetector.SIGNATURE_KINDS.size, SecretDetector.SIGNATURE_KINDS.toSet().size)
    }

    @Test
    fun everyPrivateKeyHeaderIsReportedAndPublicOnesAreNot() {
        for (h in listOf("PGP PRIVATE KEY BLOCK", "PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY")) {
            assertEquals(h, "PRIVATE_KEY", kind("-----BEGIN $h-----"))
        }
        assertNull(kind("-----BEGIN " + "PGP PUBLIC KEY BLOCK-----"))
        assertNull(kind("-----BEGIN " + "PUBLIC KEY-----"))
        assertNull(kind("-----BEGIN " + "rsa PRIVATE KEY-----"))
        assertEquals("PUTTY_PRIVATE_KEY", kind("PuTTY-User-Key-File-" + "3: ssh-ed25519"))
        assertNull(kind("PuTTY-User-Key-File-" + "4: ssh-rsa"))
    }

    @Test
    fun theLiteralFilterNeverHidesAMatch() {
        // Every rule that has literals must find its value through scanSignatures exactly as its regex alone would.
        val samples = listOf(GITHUB, "AKIA" + "Q7LM2XV9RT4KP8WZ", "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc", "xox" + "b-" + "1234567890-abcdefghij",
            "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJmYWtlIn0" + "." + "ZmFrZXNpZ25hdHVyZQ")
        for (s in samples) assertTrue(s.take(6), kind("prefix $s suffix") != null)
    }
}
