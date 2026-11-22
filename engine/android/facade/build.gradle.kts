// Drop-in replacement for com.celzero:firestack:<sha>@aar.
//  * Java: gobind-generated facade vendored verbatim by engine/tools/facade-sync.sh (src/main/java)
//  * JNI:  libgojni.so built from engine/crates/fs-jni by cargo-ndk (build/rustJniLibs)
// Properties: -PrustAbis=arm64-v8a,x86_64 (default: all four)  -PrustProfile=release|android-dev (default: release)
//             -PrustOptLevel=3|s|z (default: the profile's; for size/speed measurements)

plugins {
    id("com.android.library")
}

group = "io.github.downlz.rethinkreloaded"
version = "0.0.1"

val engineDir = rootDir.parentFile
val rustAbis = (findProperty("rustAbis")?.toString() ?: "arm64-v8a,armeabi-v7a,x86,x86_64")
    .split(',').map { it.trim() }.filter { it.isNotEmpty() }
val rustProfile = findProperty("rustProfile")?.toString() ?: "release"
val rustOptLevel = findProperty("rustOptLevel")?.toString() ?: ""
val rustOut = layout.buildDirectory.dir("rustJniLibs")

android {
    namespace = "go.intra.gojni" // same manifest package as upstream's AAR
    compileSdk = 37
    ndkVersion = findProperty("rustNdkVersion")?.toString() ?: "29.0.14206865"

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro") // upstream's proguard.txt: keep go.** and com.celzero.firestack.**
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add(rustOut.get().asFile.absolutePath)
        }
    }

    // the app also has these build types; give variant matching an exact counterpart
    buildTypes {
        create("alpha") { initWith(getByName("release")) }
        create("releaseDebug") { initWith(getByName("release")) }
        create("leakCanary") { initWith(getByName("debug")) }
    }
}

val ndkDir = androidComponents.sdkComponents.ndkDirectory

val cargoNdk by tasks.registering(Exec::class) {
    description = "Builds libgojni.so (engine/crates/fs-jni) for $rustAbis with cargo-ndk"
    group = "build"
    workingDir = engineDir
    inputs.dir(File(engineDir, "crates"))
    inputs.files(File(engineDir, "Cargo.toml"), File(engineDir, "Cargo.lock"), File(engineDir, "rust-toolchain.toml"))
    inputs.property("abis", rustAbis)
    inputs.property("profile", rustProfile)
    inputs.property("optLevel", rustOptLevel)
    outputs.dir(rustOut)
    val out = rustOut.get().asFile
    val abiArgs = rustAbis.flatMap { listOf("-t", it) }
    val ndk = ndkDir
    // plain values only: the configuration cache cannot capture script objects
    val optEnv = if (rustOptLevel.isNotEmpty()) {
        "CARGO_PROFILE_${rustProfile.uppercase().replace('-', '_')}_OPT_LEVEL" to rustOptLevel
    } else {
        null
    }
    doFirst {
        environment("ANDROID_NDK_HOME", System.getenv("ANDROID_NDK_HOME") ?: ndk.get().asFile.absolutePath)
        optEnv?.let { (k, v) -> environment(k, v) }
    }
    commandLine(
        listOf("cargo", "ndk", "--platform", "23") + abiArgs +
            listOf("-o", out.absolutePath, "build", "--locked", "--profile", rustProfile, "-p", "fs-jni")
    )
    // Split symbols out (the app module has no NDK, so AGP's strip step copies libraries unchanged): keep the
    // unstripped library for symbolizing crash reports under build/rustSymbols/<abi>/ and ship a stripped one
    // (llvm-strip --strip-all keeps .dynsym, i.e. JNI_OnLoad and the Java_* exports).
    val symbols = layout.buildDirectory.dir("rustSymbols").get().asFile
    val abis = rustAbis
    val hostTag = if (System.getProperty("os.name").lowercase().contains("mac")) "darwin-x86_64" else "linux-x86_64"
    outputs.dir(symbols)
    doLast {
        val strip = File(ndk.get().asFile, "toolchains/llvm/prebuilt/$hostTag/bin/llvm-strip")
        for (abi in abis) {
            val lib = File(out, "$abi/libgojni.so")
            if (!lib.exists()) continue
            val keep = File(symbols, "$abi/libgojni.so")
            keep.parentFile.mkdirs()
            lib.copyTo(keep, overwrite = true)
            val p = ProcessBuilder(strip.absolutePath, "--strip-all", lib.absolutePath).inheritIO().start()
            check(p.waitFor() == 0) { "llvm-strip failed for $lib" }
        }
    }
}

tasks.configureEach {
    if (name.startsWith("merge") && name.endsWith("JniLibFolders")) {
        dependsOn(cargoNdk)
    }
}
