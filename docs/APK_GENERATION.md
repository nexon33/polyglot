# APK Generation for Poly

## Overview

Generate a standalone Android APK from a .poly file containing:
1. Native Rust binary (background service/server)
2. Web UI (WebView frontend)

## Architecture

```
┌─────────────────────────────────────┐
│           Android APK               │
├─────────────────────────────────────┤
│  MainActivity (Kotlin/Java)         │
│    └─ WebView → localhost:PORT      │
├─────────────────────────────────────┤
│  NativeService                      │
│    └─ Runs native binary            │
│    └─ Starts HTTP/WS server         │
├─────────────────────────────────────┤
│  assets/                            │
│    ├─ native_binary (aarch64)       │
│    └─ web/ (html, js, css)          │
└─────────────────────────────────────┘
```

## Implementation Options

### Option 1: Minimal Wrapper APK (Recommended)

Use a pre-built APK template that:
- Extracts native binary to app data dir
- Runs it as a subprocess
- Shows WebView pointing to localhost

**Pros:** Simple, no Android SDK needed at build time
**Cons:** Limited Android integration

### Option 2: Full Gradle Build

Generate complete Android project and build with Gradle.

**Pros:** Full Android integration, Play Store ready
**Cons:** Requires Android SDK, Gradle, longer build times

### Option 3: JNI Library

Compile Rust as `.so` library with JNI bindings.

**Pros:** Native integration, no subprocess
**Cons:** Complex, requires JNI wrapper generation

## Phase 1: Minimal Wrapper (MVP)

### Pre-built Template

Create a minimal Android app template:

```kotlin
// MainActivity.kt
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Extract and run native binary
        val binary = extractAsset("native_binary")
        binary.setExecutable(true)
        
        val process = ProcessBuilder(binary.absolutePath)
            .directory(filesDir)
            .start()
        
        // Wait for server to start
        Thread.sleep(1000)
        
        // Show WebView
        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        webView.loadUrl("http://localhost:8080")
        setContentView(webView)
    }
}
```

### Build Process

```bash
poly build app.poly --target apk

# Steps:
# 1. Compile Rust → aarch64 binary
# 2. Bundle JS/HTML/CSS
# 3. Copy binary + web assets to APK template
# 4. Update AndroidManifest.xml with app name
# 5. Sign APK (debug key or user-provided)
# 6. Output: app.apk
```

### APK Template Structure

```
poly-apk-template/
├── app/
│   ├── src/main/
│   │   ├── AndroidManifest.xml
│   │   ├── kotlin/com/poly/app/
│   │   │   └── MainActivity.kt
│   │   ├── res/
│   │   │   ├── layout/activity_main.xml
│   │   │   └── values/strings.xml
│   │   └── assets/
│   │       ├── native_binary  ← injected
│   │       └── web/           ← injected
│   └── build.gradle
├── build.gradle
├── settings.gradle
└── gradle/wrapper/
```

### Without Gradle (apktool approach)

For environments without Android SDK:

1. Pre-build the APK template (one-time)
2. Use `apktool` to unpack → inject assets → repack
3. Sign with `apksigner` or `jarsigner`

```bash
# Unpack template
apktool d template.apk -o temp/

# Inject assets
cp native_binary temp/assets/
cp -r web/ temp/assets/

# Repack
apktool b temp/ -o unsigned.apk

# Sign
apksigner sign --ks debug.keystore unsigned.apk
```

## CLI Interface

```bash
# Basic APK build
poly build app.poly --target apk

# With options
poly build app.poly --target apk \
    --app-name "My App" \
    --package "com.example.myapp" \
    --icon icon.png \
    --keystore release.keystore

# Output
# → app.apk (signed, ready to install)
```

## Required Tools

### Minimal (apktool approach)
- apktool (Java)
- apksigner or jarsigner

### Full (Gradle approach)
- Android SDK
- Gradle
- Java JDK

## Implementation Plan

### Phase 1: apktool approach
1. Create pre-built APK template
2. Add `--target apk` to CLI
3. Implement asset injection
4. Implement signing

### Phase 2: Gradle approach
1. Generate full Android project
2. Integrate with Gradle build
3. Support custom icons, permissions

### Phase 3: Advanced
1. JNI library option
2. Multiple architectures (arm64, arm, x86)
3. Play Store signing

## Status

- [x] Create APK template project
- [x] Implement zip-based APK assembly (no apktool needed)
- [x] Implement debug signing
- [x] Add --target apk to CLI
- [ ] Test on physical device
- [ ] JNI library generation for exported functions
- [ ] Multiple architecture support
