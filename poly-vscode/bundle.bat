@echo off
REM Bundle script for poly-vscode extension
REM Builds Rust binaries and copies them to bin/

echo === Building Polyglot Binaries ===

REM Navigate to Rust project root
pushd ..

REM Build release binaries
echo Building release binaries...
cargo build --release

REM Create bin directory in extension
if not exist "poly-vscode\bin" mkdir "poly-vscode\bin"

REM Copy binaries
echo Copying binaries...
if exist "target\release\polyglot.exe" (
    copy /Y "target\release\polyglot.exe" "poly-vscode\bin\"
    echo   Copied polyglot.exe
)
if exist "target\release\poly-lsp.exe" (
    copy /Y "target\release\poly-lsp.exe" "poly-vscode\bin\"
    echo   Copied poly-lsp.exe
)

REM Also check for poly.exe (might be named differently)
if exist "target\release\poly.exe" (
    copy /Y "target\release\poly.exe" "poly-vscode\bin\polyglot.exe"
    echo   Copied poly.exe as polyglot.exe
)

popd

echo === Building Extension ===
call npm run compile

echo === Packaging VSIX ===
call npx @vscode/vsce package --no-dependencies --allow-missing-repository --skip-license

echo === Done! ===
echo Install with: code --install-extension poly-vscode-0.1.0.vsix
