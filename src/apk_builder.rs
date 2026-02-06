//! APK Builder - Creates Android APKs without Gradle
//!
//! Uses Android SDK tools directly:
//! - aapt2: compile and link resources
//! - d8: dex compilation  
//! - zipalign: optimize APK
//! - apksigner: sign APK

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
pub struct ApkConfig {
    pub app_name: String,
    pub package_name: String,
    pub version_code: u32,
    pub version_name: String,
    pub min_sdk: u32,
    pub target_sdk: u32,
}

impl Default for ApkConfig {
    fn default() -> Self {
        Self {
            app_name: "Poly App".to_string(),
            package_name: "com.poly.app".to_string(),
            version_code: 1,
            version_name: "1.0".to_string(),
            min_sdk: 21,
            target_sdk: 34,
        }
    }
}

#[derive(Debug)]
pub struct ApkBuilder {
    sdk_path: PathBuf,
    build_tools_path: PathBuf,
    platform_path: PathBuf,
    work_dir: PathBuf,
}

impl ApkBuilder {
    /// Find Android SDK and initialize builder
    pub fn new(work_dir: PathBuf) -> Result<Self, String> {
        let sdk_path = find_android_sdk()?;
        let build_tools_path = find_build_tools(&sdk_path)?;
        let platform_path = find_platform(&sdk_path)?;
        
        Ok(Self {
            sdk_path,
            build_tools_path,
            platform_path,
            work_dir,
        })
    }
    
    /// Build APK from native binary and web assets
    pub fn build(
        &self,
        native_binary: &[u8],
        web_assets: &[(String, Vec<u8>)], // (filename, content)
        config: &ApkConfig,
    ) -> Result<Vec<u8>, String> {
        fs::create_dir_all(&self.work_dir).map_err(|e| e.to_string())?;
        
        // 1. Generate AndroidManifest.xml
        let manifest = self.generate_manifest(config);
        let manifest_path = self.work_dir.join("AndroidManifest.xml");
        fs::write(&manifest_path, &manifest).map_err(|e| e.to_string())?;
        
        // 2. Create res directory with minimal resources
        self.create_resources(config)?;
        
        // 3. Compile resources with aapt2
        self.compile_resources()?;
        
        // 4. Link resources into base APK
        let base_apk = self.link_resources(config)?;
        
        // 5. Generate and compile Java code
        self.generate_java_code(config)?;
        self.compile_java()?;
        
        // 6. Dex the classes
        self.dex_classes()?;
        
        // 7. Create assets directory and add native binary + web files
        self.add_assets(native_binary, web_assets)?;
        
        // 8. Build final APK
        let unsigned_apk = self.build_unsigned_apk()?;
        
        // 9. Zipalign
        let aligned_apk = self.zipalign(&unsigned_apk)?;
        
        // 10. Sign
        let signed_apk = self.sign_apk(&aligned_apk)?;
        
        // Read and return the final APK
        fs::read(&signed_apk).map_err(|e| e.to_string())
    }
    
    fn generate_manifest(&self, config: &ApkConfig) -> String {
        format!(r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}"
    android:versionCode="{version_code}"
    android:versionName="{version_name}">
    
    <uses-sdk
        android:minSdkVersion="{min_sdk}"
        android:targetSdkVersion="{target_sdk}" />
    
    <uses-permission android:name="android.permission.INTERNET" />
    
    <application
        android:label="{app_name}"
        android:usesCleartextTraffic="true">
        
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:configChanges="orientation|screenSize">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
    </application>
</manifest>"#,
            package = config.package_name,
            version_code = config.version_code,
            version_name = config.version_name,
            min_sdk = config.min_sdk,
            target_sdk = config.target_sdk,
            app_name = config.app_name,
        )
    }
    
    fn create_resources(&self, config: &ApkConfig) -> Result<(), String> {
        let res_dir = self.work_dir.join("res");
        let values_dir = res_dir.join("values");
        fs::create_dir_all(&values_dir).map_err(|e| e.to_string())?;
        
        // strings.xml
        let strings = format!(r#"<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">{}</string>
</resources>"#, config.app_name);
        fs::write(values_dir.join("strings.xml"), strings).map_err(|e| e.to_string())?;
        
        // Create minimal layout
        let layout_dir = res_dir.join("layout");
        fs::create_dir_all(&layout_dir).map_err(|e| e.to_string())?;
        
        let layout = r#"<?xml version="1.0" encoding="utf-8"?>
<WebView xmlns:android="http://schemas.android.com/apk/res/android"
    android:id="@+id/webview"
    android:layout_width="match_parent"
    android:layout_height="match_parent" />"#;
        fs::write(layout_dir.join("activity_main.xml"), layout).map_err(|e| e.to_string())?;
        
        Ok(())
    }
    
    fn compile_resources(&self) -> Result<(), String> {
        let aapt2 = self.build_tools_path.join("aapt2.exe");
        let res_dir = self.work_dir.join("res");
        let compiled_dir = self.work_dir.join("compiled");
        fs::create_dir_all(&compiled_dir).map_err(|e| e.to_string())?;
        
        let output = Command::new(&aapt2)
            .arg("compile")
            .arg("--dir")
            .arg(&res_dir)
            .arg("-o")
            .arg(&compiled_dir)
            .output()
            .map_err(|e| format!("Failed to run aapt2 compile: {}", e))?;
        
        if !output.status.success() {
            return Err(format!("aapt2 compile failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
        
        Ok(())
    }
    
    fn link_resources(&self, config: &ApkConfig) -> Result<PathBuf, String> {
        let aapt2 = self.build_tools_path.join("aapt2.exe");
        let android_jar = self.platform_path.join("android.jar");
        let manifest = self.work_dir.join("AndroidManifest.xml");
        let compiled_dir = self.work_dir.join("compiled");
        let output_apk = self.work_dir.join("base.apk");
        
        // Collect all .flat files
        let flat_files: Vec<PathBuf> = fs::read_dir(&compiled_dir)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map_or(false, |ext| ext == "flat"))
            .collect();
        
        let mut cmd = Command::new(&aapt2);
        cmd.arg("link")
            .arg("-I").arg(&android_jar)
            .arg("--manifest").arg(&manifest)
            .arg("-o").arg(&output_apk)
            .arg("--auto-add-overlay")
            .arg("--java").arg(self.work_dir.join("gen"));
        
        for flat in &flat_files {
            cmd.arg(flat);
        }
        
        let output = cmd.output()
            .map_err(|e| format!("Failed to run aapt2 link: {}", e))?;
        
        if !output.status.success() {
            return Err(format!("aapt2 link failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
        
        Ok(output_apk)
    }
    
    fn generate_java_code(&self, config: &ApkConfig) -> Result<(), String> {
        let java_dir = self.work_dir.join("src");
        let package_dir = java_dir.join(config.package_name.replace('.', "/"));
        fs::create_dir_all(&package_dir).map_err(|e| e.to_string())?;
        
        let main_activity = format!(r#"package {package};

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebSettings;
import java.io.*;

public class MainActivity extends Activity {{
    private Process nativeProcess;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        
        // Extract and run native binary
        try {{
            File binary = extractAsset("native_binary");
            binary.setExecutable(true);
            ProcessBuilder pb = new ProcessBuilder(binary.getAbsolutePath());
            pb.directory(getFilesDir());
            pb.redirectErrorStream(true);
            nativeProcess = pb.start();
            
            // Give the server time to start
            Thread.sleep(500);
        }} catch (Exception e) {{
            e.printStackTrace();
        }}
        
        // Setup WebView
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        
        webView.setWebViewClient(new WebViewClient());
        
        // Load web UI from assets or localhost
        webView.loadUrl("file:///android_asset/web/index.html");
        
        setContentView(webView);
    }}
    
    private File extractAsset(String name) throws IOException {{
        File outFile = new File(getFilesDir(), name);
        if (!outFile.exists()) {{
            InputStream in = getAssets().open(name);
            FileOutputStream out = new FileOutputStream(outFile);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {{
                out.write(buffer, 0, read);
            }}
            in.close();
            out.close();
        }}
        return outFile;
    }}
    
    @Override
    protected void onDestroy() {{
        super.onDestroy();
        if (nativeProcess != null) {{
            nativeProcess.destroy();
        }}
    }}
}}"#, package = config.package_name);
        
        fs::write(package_dir.join("MainActivity.java"), main_activity)
            .map_err(|e| e.to_string())?;
        
        Ok(())
    }
    
    fn compile_java(&self) -> Result<(), String> {
        let android_jar = self.platform_path.join("android.jar");
        let src_dir = self.work_dir.join("src");
        let gen_dir = self.work_dir.join("gen");
        let classes_dir = self.work_dir.join("classes");
        fs::create_dir_all(&classes_dir).map_err(|e| e.to_string())?;
        
        // Find all .java files
        let java_files: Vec<PathBuf> = walkdir(&src_dir)
            .into_iter()
            .chain(walkdir(&gen_dir).into_iter())
            .filter(|p| p.extension().map_or(false, |ext| ext == "java"))
            .collect();
        
        if java_files.is_empty() {
            return Err("No Java files found".to_string());
        }
        
        let mut cmd = Command::new("javac");
        cmd.arg("-source").arg("1.8")
            .arg("-target").arg("1.8")
            .arg("-bootclasspath").arg(&android_jar)
            .arg("-d").arg(&classes_dir);
        
        for java_file in &java_files {
            cmd.arg(java_file);
        }
        
        let output = cmd.output()
            .map_err(|e| format!("Failed to run javac: {}", e))?;
        
        if !output.status.success() {
            return Err(format!("javac failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
        
        Ok(())
    }
    
    fn dex_classes(&self) -> Result<(), String> {
        let d8 = self.build_tools_path.join("d8.bat");
        let classes_dir = self.work_dir.join("classes");
        let dex_dir = self.work_dir.join("dex");
        fs::create_dir_all(&dex_dir).map_err(|e| e.to_string())?;
        
        // Find all .class files
        let class_files: Vec<PathBuf> = walkdir(&classes_dir)
            .into_iter()
            .filter(|p| p.extension().map_or(false, |ext| ext == "class"))
            .collect();
        
        let mut cmd = Command::new("cmd");
        cmd.arg("/c").arg(&d8)
            .arg("--output").arg(&dex_dir)
            .arg("--min-api").arg("21");
        
        for class_file in &class_files {
            cmd.arg(class_file);
        }
        
        let output = cmd.output()
            .map_err(|e| format!("Failed to run d8: {}", e))?;
        
        if !output.status.success() {
            return Err(format!("d8 failed: {}", String::from_utf8_lossy(&output.stderr)));
        }
        
        Ok(())
    }
    
    fn add_assets(&self, native_binary: &[u8], web_assets: &[(String, Vec<u8>)]) -> Result<(), String> {
        let assets_dir = self.work_dir.join("assets");
        let web_dir = assets_dir.join("web");
        fs::create_dir_all(&web_dir).map_err(|e| e.to_string())?;
        
        // Write native binary
        fs::write(assets_dir.join("native_binary"), native_binary)
            .map_err(|e| e.to_string())?;
        
        // Write web assets
        for (name, content) in web_assets {
            fs::write(web_dir.join(name), content)
                .map_err(|e| e.to_string())?;
        }
        
        Ok(())
    }
    
    fn build_unsigned_apk(&self) -> Result<PathBuf, String> {
        let base_apk = self.work_dir.join("base.apk");
        let dex_file = self.work_dir.join("dex/classes.dex");
        let assets_dir = self.work_dir.join("assets");
        let unsigned_apk = self.work_dir.join("unsigned.apk");
        
        // Copy base.apk to unsigned.apk
        fs::copy(&base_apk, &unsigned_apk).map_err(|e| e.to_string())?;
        
        // Add dex and assets using zip
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&unsigned_apk)
            .map_err(|e| e.to_string())?;
        
        let mut zip = zip::ZipWriter::new_append(file)
            .map_err(|e| e.to_string())?;
        
        // Add classes.dex
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        
        zip.start_file("classes.dex", options).map_err(|e| e.to_string())?;
        let dex_bytes = fs::read(&dex_file).map_err(|e| e.to_string())?;
        zip.write_all(&dex_bytes).map_err(|e| e.to_string())?;
        
        // Add assets
        for entry in walkdir(&assets_dir) {
            if entry.is_file() {
                let relative = entry.strip_prefix(&self.work_dir).unwrap();
                let name = relative.to_string_lossy().replace("\\", "/");
                zip.start_file(&name, options).map_err(|e| e.to_string())?;
                let content = fs::read(&entry).map_err(|e| e.to_string())?;
                zip.write_all(&content).map_err(|e| e.to_string())?;
            }
        }
        
        // Add native library for aarch64
        let lib_dir = format!("lib/arm64-v8a");
        zip.add_directory(&lib_dir, options).map_err(|e| e.to_string())?;
        
        zip.finish().map_err(|e| e.to_string())?;
        
        Ok(unsigned_apk)
    }
    
    fn zipalign(&self, input: &Path) -> Result<PathBuf, String> {
        let zipalign = self.build_tools_path.join("zipalign.exe");
        let output = self.work_dir.join("aligned.apk");
        
        let result = Command::new(&zipalign)
            .arg("-f")
            .arg("-v")
            .arg("4")
            .arg(input)
            .arg(&output)
            .output()
            .map_err(|e| format!("Failed to run zipalign: {}", e))?;
        
        if !result.status.success() {
            return Err(format!("zipalign failed: {}", String::from_utf8_lossy(&result.stderr)));
        }
        
        Ok(output)
    }
    
    fn sign_apk(&self, input: &Path) -> Result<PathBuf, String> {
        let output = self.work_dir.join("app.apk");
        
        // Generate or use debug keystore
        let keystore = self.work_dir.join("debug.keystore");
        if !keystore.exists() {
            self.generate_debug_keystore(&keystore)?;
        }
        
        // Use apksigner
        let apksigner_jar = self.build_tools_path.join("lib/apksigner.jar");
        
        let result = Command::new("java")
            .arg("-jar")
            .arg(&apksigner_jar)
            .arg("sign")
            .arg("--ks").arg(&keystore)
            .arg("--ks-pass").arg("pass:android")
            .arg("--out").arg(&output)
            .arg(input)
            .output()
            .map_err(|e| format!("Failed to run apksigner: {}", e))?;
        
        if !result.status.success() {
            return Err(format!("apksigner failed: {}", String::from_utf8_lossy(&result.stderr)));
        }
        
        Ok(output)
    }
    
    fn generate_debug_keystore(&self, path: &Path) -> Result<(), String> {
        let result = Command::new("keytool")
            .arg("-genkeypair")
            .arg("-v")
            .arg("-keystore").arg(path)
            .arg("-alias").arg("androiddebugkey")
            .arg("-keyalg").arg("RSA")
            .arg("-keysize").arg("2048")
            .arg("-validity").arg("10000")
            .arg("-storepass").arg("android")
            .arg("-keypass").arg("android")
            .arg("-dname").arg("CN=Android Debug,O=Android,C=US")
            .output()
            .map_err(|e| format!("Failed to run keytool: {}", e))?;
        
        if !result.status.success() {
            return Err(format!("keytool failed: {}", String::from_utf8_lossy(&result.stderr)));
        }
        
        Ok(())
    }
}

/// Find Android SDK path
fn find_android_sdk() -> Result<PathBuf, String> {
    // Check ANDROID_HOME or ANDROID_SDK_ROOT
    if let Ok(sdk) = std::env::var("ANDROID_HOME") {
        let path = PathBuf::from(&sdk);
        if path.exists() {
            return Ok(path);
        }
    }
    if let Ok(sdk) = std::env::var("ANDROID_SDK_ROOT") {
        let path = PathBuf::from(&sdk);
        if path.exists() {
            return Ok(path);
        }
    }
    
    // Check common locations
    let home = dirs::home_dir().ok_or("Cannot find home directory")?;
    let common_paths = [
        home.join("AppData/Local/Android/Sdk"),
        home.join("Android/Sdk"),
        PathBuf::from("C:/Android/Sdk"),
    ];
    
    for path in &common_paths {
        if path.exists() {
            return Ok(path.clone());
        }
    }
    
    Err("Android SDK not found. Set ANDROID_HOME or install Android Studio.".to_string())
}

/// Find latest build-tools version
fn find_build_tools(sdk: &Path) -> Result<PathBuf, String> {
    let build_tools = sdk.join("build-tools");
    if !build_tools.exists() {
        return Err("build-tools not found in SDK".to_string());
    }
    
    let mut versions: Vec<_> = fs::read_dir(&build_tools)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    
    versions.sort_by(|a, b| b.path().cmp(&a.path()));
    
    versions.first()
        .map(|e| e.path())
        .ok_or("No build-tools version found".to_string())
}

/// Find platform (android.jar)
fn find_platform(sdk: &Path) -> Result<PathBuf, String> {
    let platforms = sdk.join("platforms");
    if !platforms.exists() {
        return Err("platforms not found in SDK".to_string());
    }
    
    let mut versions: Vec<_> = fs::read_dir(&platforms)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("android.jar").exists())
        .collect();
    
    versions.sort_by(|a, b| b.path().cmp(&a.path()));
    
    versions.first()
        .map(|e| e.path())
        .ok_or("No platform with android.jar found".to_string())
}

/// Walk directory recursively
fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walkdir(&path));
            } else {
                files.push(path);
            }
        }
    }
    files
}
