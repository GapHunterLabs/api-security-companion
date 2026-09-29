import org.jetbrains.intellij.platform.gradle.TestFrameworkType
import org.jetbrains.intellij.platform.gradle.tasks.VerifyPluginTask

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.intellij.platform")
    id("org.jetbrains.changelog")
}

dependencies {
    testImplementation("junit:junit:4.13.2")

    // Powers the Pro-tier "reduce false positives on generic high-entropy
    // secret matches" rule (SecurityRule.ML_FALSE_POSITIVE_REDUCTION) --
    // runs the bundled secret_classifier.onnx (20KB, see
    // ml-training/README.md) 100% on-device. KInference (JetBrains-
    // Research), not com.microsoft.onnxruntime: the official native
    // ONNX Runtime Java binding crashes the JVM
    // (EXCEPTION_ACCESS_VIOLATION in msvcp140.dll) the moment it
    // initializes inside a process hosted by the JetBrains Runtime --
    // confirmed via a real crash log, not a hypothetical -- because JBR
    // already loads its own, incompatible copy of that DLL. KInference's
    // inference-core-jvm is pure JVM bytecode (verified: no .dll/.so in
    // the jar), so there is no native library to collide with JBR's in
    // the first place.
    //
    // Excludes KInference's own kotlinx-coroutines-core (pulls 1.9.0):
    // that jar landing on testRuntimeClasspath (confirmed via
    // `./gradlew dependencies`) lines up exactly with a real
    // BasePlatformTestCase test failure that appeared the same build
    // this dependency was added --
    // `NoSuchMethodError: ...IntellijCoroutines.runBlockingWithParallelismCompensation`
    // (that JetBrains-internal method isn't in the plain 1.9.0 release
    // from Maven Central). Excluding it here so the platform's own
    // bundled coroutines runtime is what's actually on the classpath at
    // test/runtime time -- nothing in this file needs KInference's own
    // copy specifically, only plain `runBlocking` is used.
    implementation("io.kinference:inference-core-jvm:0.2.27") {
        exclude(group = "org.jetbrains.kotlinx", module = "kotlinx-coroutines-core")
        exclude(group = "org.jetbrains.kotlinx", module = "kotlinx-coroutines-core-jvm")
    }

    intellijPlatform {
        intellijIdea("2025.2.6.2")

        bundledPlugin("com.intellij.java")
        bundledPlugin("org.jetbrains.kotlin")
        bundledPlugin("org.jetbrains.plugins.yaml")
        bundledPlugin("com.intellij.modules.json")
        bundledPlugin("com.intellij.properties")

        testFramework(TestFrameworkType.Platform)
    }
}

// Precision run on a real corpus (see ConfigCorpusPrecisionTest): only when -Papisec.corpus=<dir> is given.
tasks.withType<Test>().configureEach {
    listOf("apisec.corpus", "apisec.corpus.report").forEach { key ->
        providers.gradleProperty(key).orNull?.let { systemProperty(key, it) }
    }
}

intellijPlatform {
    pluginConfiguration {
        ideaVersion {
            // 243 = 2024.3, so as not to exclude the real installed base.
            sinceBuild = "243"
            untilBuild = provider { null }
        }
    }

    // Same tooling bug as the other Gap Hunter Labs plugins (Gradle 9.5 +
    // IntelliJ Platform Gradle Plugin 2.16 + IDE 2025.2.6.2): the
    // bytecode instrumenter fails with "instrumentIdeaExtensions
    // doesn't support the nested element". Not required for
    // build/test/verifyPlugin.
    instrumentCode = false

    // Catch experimental/internal API usage locally, before Marketplace's
    // own verifier flags it post-upload — this is what caught the
    // PsiExternalReferenceHost warning that motivated adding this block.
    pluginVerification {
        failureLevel = listOf(
            VerifyPluginTask.FailureLevel.COMPATIBILITY_PROBLEMS,
            VerifyPluginTask.FailureLevel.INTERNAL_API_USAGES,
            VerifyPluginTask.FailureLevel.OVERRIDE_ONLY_API_USAGES,
            VerifyPluginTask.FailureLevel.EXPERIMENTAL_API_USAGES,
            VerifyPluginTask.FailureLevel.SCHEDULED_FOR_REMOVAL_API_USAGES,
        )
    }

    // Publish token read from a LOCAL, non-repo Gradle property
    // (~/.gradle/gradle.properties, never committed) -- never hardcoded
    // here. Falls back to null (task fails loudly asking for the token)
    // if that file doesn't define it, rather than silently no-op-ing.
    publishing {
        token.set(providers.gradleProperty("gapHunterLabs.marketplace.token"))
    }

    // Same pattern: signing material lives only in the local, non-repo
    // gradle.properties (self-signed cert generated once for the whole
    // catalog, 10-year validity).
    signing {
        certificateChain.set(providers.gradleProperty("gapHunterLabs.marketplace.certificateChain"))
        privateKey.set(providers.gradleProperty("gapHunterLabs.marketplace.privateKey"))
        password.set(providers.gradleProperty("gapHunterLabs.marketplace.privateKeyPassword"))
    }
}

// Demo fixtures that need well-formed (fake) tokens for the manual runIde test. They are
// GENERATED, never committed: GitHub's push protection blocks a well-formed token in any
// committed file, even a fake one (demo/generated/ is in .gitignore).
// Run `./gradlew writeDemoSecrets`, then `./gradlew runIde` and open the demo project.
tasks.register("writeDemoSecrets") {
    val outDir = layout.projectDirectory.dir("demo/generated").asFile
    outputs.dir(outDir)
    doLast {
        fun body(n: Int, alphabet: String = "aB3dE9gH2jK5mN8pQ1sT4vW7yZ0cF6hJ9lO2rU5xC8") =
            (0 until n).map { alphabet[(it * 7 + 3) % alphabet.length] }.joinToString("")

        val openAi = "sk-" + "proj-" + body(80)
        val anthropic = "sk-" + "ant-" + "api03-" + body(93) + "AA"
        val hf = "hf_" + body(34, "abcdefghijklmnopqrstuvwxyzABCDEFGH")
        val ghPat = "github_" + "pat_" + body(82)
        outDir.mkdirs()
        File(outDir, "mcp.json").writeText(
            """
            {
              "mcpServers": {
                "search": {
                  "command": "npx",
                  "args": ["-y", "search-mcp", "--api-key=$openAi"],
                  "env": { "OPENAI_API_KEY": "$openAi", "SAFE_KEY": "${'$'}{OPENAI_API_KEY}" }
                },
                "models": {
                  "url": "https://models.example.com/mcp",
                  "headers": { "Authorization": "Bearer $hf" }
                }
              }
            }
            """.trimIndent() + "\n",
        )
        File(outDir, ".env").writeText("# expected: 3 warnings (OpenAI, Anthropic, Hugging Face); the reference is fine\nOPENAI_API_KEY=$openAi\nexport ANTHROPIC_API_KEY=\"$anthropic\"\nHF_TOKEN='$hf'\nUSES_REFERENCE=${'$'}{OPENAI_API_KEY}\nPORT=8080\n")
        File(outDir, ".env.example").writeText("# skipped on purpose: template files hold placeholders\nOPENAI_API_KEY=$openAi\n")
        File(outDir, "application.yml").writeText(
            "ai:\n  provider:\n    api-key: $anthropic\n" +
                "spring:\n  datasource:\n    password: Tt9!kQ2#mZp7@Lc4dW1&   # Pro: name + entropy heuristic\n" +
                "openapi-sample:\n  example: $openAi   # skipped: sample data\n",
        )
        File(outDir, "application.properties").writeText("github.token=$ghPat\nserver.port=8080\ntoken.url=https://auth.example.com/oauth/token\n")
        File(outDir, "README.txt").writeText(
            "Generated by ./gradlew writeDemoSecrets -- not committed.\n" +
                "Open each file in the sandbox IDE: known-format tokens get a 'Potential secret' warning (Free);\n" +
                "the password in application.yml only with a Pro license (or a team policy forcing configSecretHeuristic).\n",
        )
        println("Demo fixtures written to $outDir")
    }
}

// Local testing of the Pro features: a sandbox IDE has no Marketplace
// license. The switch that opens them (src/devSandbox) is compiled only with
// `-PdevSandbox=true`, which only local runIde sessions pass; every other
// build -- tests, buildPlugin, signPlugin, publishPlugin -- compiles the
// always-closed version in src/release, so the published plugin never
// contains it.
val devSandbox = providers.gradleProperty("devSandbox").orNull == "true"
kotlin.sourceSets["main"].kotlin.srcDir(if (devSandbox) "src/devSandbox/kotlin" else "src/release/kotlin")
kotlin.sourceSets["test"].kotlin.srcDir(if (devSandbox) "src/devSandboxTest/kotlin" else "src/releaseTest/kotlin")
if (devSandbox) {
    tasks.withType<JavaExec>().matching { it.name.startsWith("runIde") }.configureEach {
        jvmArgs("-Dapisecuritycompanion.pro.dev=true")
    }
}
