import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "1.9.21"
    id("org.jetbrains.intellij") version "1.16.1"
    id("org.jetbrains.kotlin.plugin.serialization") version "1.9.21"
}

group   = "io.ghost.security"
version = "1.0.0"

repositories { mavenCentral() }

intellij {
    version.set("2023.3")
    type.set("IC")
    plugins.set(listOf(
        "PythonCore",
        "org.jetbrains.plugins.go:233.14015.81",
    ))
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
    testImplementation("junit:junit:4.13.2")
}

tasks {
    withType<KotlinCompile> {
        kotlinOptions.jvmTarget = "17"
    }
    withType<JavaCompile> {
        sourceCompatibility = "17"
        targetCompatibility = "17"
    }
    patchPluginXml {
        sinceBuild.set("233")
        untilBuild.set("241.*")
        changeNotes.set("""
            <b>1.0.0</b>
            <ul>
                <li>Initial release</li>
                <li>Python, Java, Kotlin, Go support</li>
                <li>250+ security rules via Ghost API</li>
                <li>AI explanations via Claude/GPT/Ollama</li>
                <li>Quick-fix actions</li>
                <li>Findings tool window</li>
            </ul>
        """)
    }
    signPlugin {
        certificateChain.set(System.getenv("CERTIFICATE_CHAIN") ?: "")
        privateKey.set(System.getenv("PRIVATE_KEY") ?: "")
        password.set(System.getenv("PRIVATE_KEY_PASSWORD") ?: "")
    }
    publishPlugin {
        token.set(System.getenv("PUBLISH_TOKEN") ?: "")
    }
}
