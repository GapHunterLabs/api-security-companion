package dev.gaphunter.apisecuritycompanion.annotator

import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import java.io.File

/**
 * Precision check on a REAL corpus of configuration files (public third-party JSON/YAML/.properties/.env),
 * run through the real annotator. Skipped unless `-Papisec.corpus=<dir>` is given, so a normal
 * `./gradlew test` never touches it; the corpus lives outside the repo and is never committed.
 *
 * Two passes -- exact formats only (Free) and with the Pro heuristic forced on -- and a tab-separated
 * report `pass, file, line, warning`. Warnings only ever show a short token prefix or a key name, never a
 * value; the point is that everything reported here is a false positive to review by hand.
 */
class ConfigCorpusPrecisionTest : BasePlatformTestCase() {

    override fun tearDown() {
        try {
            ConfigSecretAnnotator.forceHeuristicForTests = null
        } finally {
            super.tearDown()
        }
    }

    fun testCorpus() {
        val root = System.getProperty("apisec.corpus")?.let(::File) ?: return
        val reportFile = File(System.getProperty("apisec.corpus.report") ?: "config-corpus-report.tsv")
        // java.nio rather than File.walkTopDown(): the test IDE bundles an older Kotlin stdlib than the one compiled against
        // (NoSuchMethodError on SequencesKt.sequenceOf), and this file never needs a Kotlin Sequence.
        val files = ArrayList<File>()
        java.nio.file.Files.walk(root.toPath()).use { stream ->
            stream.forEach { if (java.nio.file.Files.isRegularFile(it)) files.add(it.toFile()) }
        }
        files.sortBy { it.path }
        val report = StringBuilder()
        for (heuristic in listOf(false, true)) {
            ConfigSecretAnnotator.forceHeuristicForTests = heuristic
            var hits = 0
            var harnessErrors = 0
            for (file in files) {
                val text = try { file.readText() } catch (e: Exception) { continue }
                val infos = try {
                    myFixture.configureByText(file.name, text)
                    myFixture.doHighlighting()
                } catch (e: Throwable) {
                    // The test classpath's Kotlin stdlib is older than the one the IDE's own JSON-schema code was built
                    // against, so highlighting some schema-mapped JSON files (package.json, ...) throws inside the IDE,
                    // not in this plugin. Counted and skipped; the real IDE has its own stdlib.
                    harnessErrors++
                    continue
                }
                val document = myFixture.editor.document
                for (info in infos) {
                    if (info.severity != HighlightSeverity.WARNING || info.description?.startsWith("Potential secret") != true) continue
                    hits++
                    val line = document.getLineNumber(info.startOffset) + 1
                    report.append(if (heuristic) "HEURISTIC" else "EXACT").append('\t')
                        .append(file.relativeTo(root).path).append('\t').append(line).append('\t')
                        .append(info.description!!.take(140)).append('\n')
                }
            }
            report.append("# pass=").append(if (heuristic) "heuristic" else "exact").append(" files=").append(files.size)
                .append(" warnings=").append(hits).append(" skipped_by_ide_errors=").append(harnessErrors).append('\n')
        }
        reportFile.writeText(report.toString())
    }
}
