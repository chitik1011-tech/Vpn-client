plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.aurora.vpn"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.aurora.vpn"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        ndk { abiFilters += "arm64-v8a" }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Signing keys and passwords are only supplied by GitHub Secrets / environment.
    // Debug builds and local unsigned release builds need no signing secrets.
    val keyStorePath = System.getenv("VPN_RELEASE_KEYSTORE")
    val keyStorePassword = System.getenv("VPN_RELEASE_STORE_PASSWORD")
    val keyAliasName = System.getenv("VPN_RELEASE_KEY_ALIAS")
    val keyAliasPassword = System.getenv("VPN_RELEASE_KEY_PASSWORD")
    if (!keyStorePath.isNullOrBlank() &&
        !keyStorePassword.isNullOrBlank() &&
        !keyAliasName.isNullOrBlank() &&
        !keyAliasPassword.isNullOrBlank()) {
        signingConfigs {
            create("secureRelease") {
                storeFile = file(keyStorePath)
                storePassword = keyStorePassword
                keyAlias = keyAliasName
                keyPassword = keyAliasPassword
            }
        }
        buildTypes {
            getByName("release") {
                signingConfig = signingConfigs.getByName("secureRelease")
                isMinifyEnabled = false
            }
        }
    }

    buildFeatures { compose = true; buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }
    kotlinOptions { jvmTarget = "17" }

    packaging {
        jniLibs { useLegacyPackaging = true }
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.04.01"))
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.0")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.datastore:datastore-preferences:1.1.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // Android native sing-box implementation, including ARM64 binaries.
    implementation("com.github.singbox-android:libbox:1.14.0")
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
