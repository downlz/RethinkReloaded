// RethinkReloaded engine: standalone Gradle build producing the drop-in firestack AAR
// (vendored gobind Java facade + Rust libgojni.so). Included by the app when -PfirestackRepo=rust.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") {
            // share the app's catalog so AGP / Kotlin versions always match the app
            from(files("../../gradle/lib.toml"))
        }
    }
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "rethinkreloaded-engine"
include(":firestack-rust")
include(":host-test")
project(":firestack-rust").projectDir = file("facade")
