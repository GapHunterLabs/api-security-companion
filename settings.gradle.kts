import org.jetbrains.intellij.platform.gradle.extensions.intellijPlatform

rootProject.name = "api-security-companion"

pluginManagement {
    plugins {
        id("org.jetbrains.kotlin.jvm") version "2.1.20"
        id("org.jetbrains.changelog") version "2.5.0"
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
    id("org.jetbrains.intellij.platform.settings") version "2.16.0"
}

@Suppress("UnstableApiUsage")
dependencyResolutionManagement {
    repositories {
        mavenCentral()

        // KInference (JetBrains-Research) -- pure-JVM ONNX inference, no
        // native binary. Used instead of com.microsoft.onnxruntime: that
        // native binding crashes with EXCEPTION_ACCESS_VIOLATION the
        // moment it initializes inside a JetBrains-Runtime-hosted process
        // (msvcp140.dll conflict against JBR's own bundled copy -- real,
        // reproduced crash, see the class doc on MlClassifierService.kt).
        // KInference has no native library to collide with JBR in the
        // first place.
        maven { url = uri("https://packages.jetbrains.team/maven/p/ki/maven") }
        maven { url = uri("https://packages.jetbrains.team/maven/p/grazi/grazie-platform-public") }

        intellijPlatform {
            defaultRepositories()
        }
    }
}
