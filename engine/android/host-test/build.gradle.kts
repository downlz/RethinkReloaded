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

// -PrustHostLibDir=<dir>: test a prebuilt libgojni (e.g. an AddressSanitizer build) instead of building one;
// -PhostPreload=<dylib/so>: preload a library into the test JVM (the sanitizer runtime, which the JVM lacks).
val hostLibDir = findProperty("rustHostLibDir")?.toString()
val hostPreload = findProperty("hostPreload")?.toString()

tasks.test {
    if (hostLibDir == null) dependsOn(cargoHost)
    systemProperty("java.library.path", hostLibDir ?: File(engineDir, "target/debug").absolutePath)
    hostPreload?.let {
        environment("DYLD_INSERT_LIBRARIES", it)
        environment("LD_PRELOAD", it)
        environment("ASAN_OPTIONS", "detect_leaks=0:handle_segv=0:allow_user_segv_handler=1")
    }
    // like Android's CheckJNI, where JNI misuse (e.g. a call with an exception pending) aborts the app. HotSpot only
    // prints "WARNING in native method" to the worker's stdout, which CI greps for (.github/workflows/rr-ci.yml).
    jvmArgs("-Xcheck:jni")
    outputs.upToDateWhen { false } // the native library is not a declared input
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
