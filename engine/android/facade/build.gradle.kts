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
}

tasks.configureEach {
    if (name.startsWith("merge") && name.endsWith("JniLibFolders")) {
        dependsOn(cargoNdk)
    }
}
