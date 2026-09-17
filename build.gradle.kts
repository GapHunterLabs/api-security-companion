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

        testFramework(TestFrameworkType.Platform)
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
