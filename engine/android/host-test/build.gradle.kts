// Host JVM tests of the real JNI path: the vendored gobind Java facade (../facade/src/main/java) runs on the desktop
// JVM against a host build of libgojni (cargo build -p fs-jni). Unlike the app's Robolectric tests (which shadow the
// native library), these exercise refnums, struct proxies, Go-style exceptions and GC -> Seq.destroyRef for real.
//
//   ./gradlew -p engine/android :host-test:test      (from the repo root)

plugins {
    java
}

val engineDir = rootDir.parentFile

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}

sourceSets {
    main {
        java.srcDirs("../facade/src/main/java", "src/stubs/java")
    }
}

dependencies {
    testImplementation(libs.junitJunit)
}

val cargoHost by tasks.registering(Exec::class) {
    description = "Builds the host libgojni (debug) for JVM tests"
    workingDir = engineDir
    inputs.dir(File(engineDir, "crates"))
    inputs.files(File(engineDir, "Cargo.toml"), File(engineDir, "Cargo.lock"))
    outputs.dir(File(engineDir, "target/debug"))
    commandLine("cargo", "build", "--locked", "-p", "fs-jni")
}

tasks.test {
    dependsOn(cargoHost)
    systemProperty("java.library.path", File(engineDir, "target/debug").absolutePath)
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
