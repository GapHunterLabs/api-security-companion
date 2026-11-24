package dev.gaphunter.apisecuritycompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Two failures on long values, found by the stress suite of secret-scanner-cli (which ports these rules):
 *  - the slug check `[a-z]+([_.-][a-z]+)+` runs its repeated group recursively in Java, one stack frame per word, so a
 *    1 MB value like `a.a.a...` under a credential key threw StackOverflowError out of the configuration inspection;
 *  - the JWT rule started at every `\b`, so a long `-eyJ-eyJ...` run without a dot was scanned once per `eyJ`:
 *    quadratic time.
 */
class LongValueRegressionTest {

    @Test(timeout = 10_000)
    fun `a megabyte dotted value under a credential key does not overflow the stack`() {
        val value = "a.".repeat(500_000) + "a"
        assertTrue(ConfigSecretScanner.isSlug(value))
        assertNull(ConfigSecretScanner.scanValue(value, ConfigContext("password"), heuristicEnabled = true))
        assertNull(ConfigSecretScanner.scanValue("A_".repeat(500_000) + "A", ConfigContext("API_TOKEN"), heuristicEnabled = true))
    }

    @Test
    fun `the slug loop agrees with the former regex on every short string`() {
        val lower = Regex("""[a-z]+([_.-][a-z]+)+""")
        val upper = Regex("""[A-Z]+([_.-][A-Z]+)+""")
        val alphabet = listOf('a', 'b', 'Z', '_', '.', '-', '1')
        var checked = 0
        fun walk(prefix: String) {
            if (prefix.isNotEmpty()) {
                assertEquals("'$prefix'", lower.matches(prefix) || upper.matches(prefix), ConfigSecretScanner.isSlug(prefix))
                checked++
            }
            if (prefix.length < 6) for (c in alphabet) walk(prefix + c)
        }
        walk("")
        assertTrue(checked > 100_000)
    }

    @Test(timeout = 5_000)
    fun `a long dotless JWT lookalike run is linear`() {
        // With `\b` this took about 2.3 s for 20,000 characters and grew with the square of the length.
        assertNull(SecretDetector.scanSignatures("-eyJ".repeat(50_000)))
    }

    @Test
    fun `a JWT is still found at the start, after a space, a quote or an equals sign`() {
        val jwt = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJmYWtlIn0" + "." + "ZmFrZXNpZ25hdHVyZQ"
        for (text in listOf(jwt, "token $jwt", "\"$jwt\"", "t=$jwt", "Bearer $jwt")) {
            assertEquals(text, "JWT", SecretDetector.scanSignatures(text)?.kind)
        }
        // The one change in what matches: a JWT glued to a preceding base64url character is not reported.
        assertNull(SecretDetector.scanSignatures("x-$jwt"))
        assertNotNull(SecretDetector.scanSignatures("x $jwt"))
    }
}
