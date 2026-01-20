@echo off
REM Bundle polyglot binaries into the VS Code extension

echo Building Polyglot release binaries...
cd /d "%~dp0.."
cargo build --release
if errorlevel 1 exit /b 1

echo Creating bin directory...
if not exist "%~dp0bin" mkdir "%~dp0bin"

echo Copying binaries...
copy /y "target\release\polyglot.exe" "%~dp0bin\"
copy /y "target\release\poly-lsp.exe" "%~dp0bin\"

echo Compiling TypeScript...
cd /d "%~dp0"
call npm run compile
if errorlevel 1 exit /b 1

echo Packaging extension...
call npx vsce package

echo Done! Extension packaged with bundled binaries.
dir /b *.vsix
