package dev.gaphunter.apisecuritycompanion.settings

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import java.util.concurrent.ConcurrentHashMap

/**
 * "Team rules shared via VCS" (Pro tier): a `.gaphunter-security-rules`
 * file at the project root, one rule ID per line (`#` for comments,
 * matching `SecurityRule.id`), committed to the repo like any other
 * project file. Any rule ID listed there is enforced for every team
 * member who opens this project, regardless of what they've disabled
 * locally in Settings -- the whole point is a rule an individual can't
 * silently opt out of once the team has agreed to it.
 *
 * Deliberately a plain line-based text format, not JSON/YAML -- no
 * parser needed at all, trivially git-diff-friendly, and this plugin
 * already has no JSON-parsing utility to reach for (unlike
 * format-converter-companion/k6-companion/firestore-companion, which
 * each hand-roll their own for unrelated reasons).
 *
 * Reads via `VirtualFile.contentsToByteArray()`, not a
 * `FileTypeOverrider`/`FileTypeDetector` context, so the real infinite-
 * recursion risk that pattern is prone to doesn't apply here.
 */
object TeamPolicyLoader {
    const val POLICY_FILE_NAME = ".gaphunter-security-rules"
    private const val CACHE_TTL_MS = 5_000L

    private data class CacheEntry(val ruleIds: Set<String>, val readAtMs: Long)

    private val cache = ConcurrentHashMap<String, CacheEntry>()

    fun forcedRuleIds(project: Project): Set<String> {
        val basePath = project.basePath ?: return emptySet()
        val now = System.currentTimeMillis()
        val cached = cache[basePath]
        if (cached != null && now - cached.readAtMs < CACHE_TTL_MS) return cached.ruleIds

        val ruleIds = readRuleIds(basePath)
        cache[basePath] = CacheEntry(ruleIds, now)
        return ruleIds
    }

    private fun readRuleIds(basePath: String): Set<String> {
        val file = LocalFileSystem.getInstance().findFileByPath("$basePath/$POLICY_FILE_NAME") ?: return emptySet()
        val text = try {
            String(file.contentsToByteArray(), Charsets.UTF_8)
        } catch (e: Exception) {
            return emptySet()
        }
        return parseRuleIds(text)
    }

    /** Exposed separately from [forcedRuleIds] so it's testable with plain
     * strings, no `Project`/`VirtualFile` fixture required. */
    fun parseRuleIds(text: String): Set<String> =
        text.lineSequence()
            .map { it.substringBefore('#').trim() }
            .filter { it.isNotEmpty() }
            .toSet()
}
