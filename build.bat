@echo off
REM ============================================================
REM  Cloudflare WARP Split Console - build script
REM  Packs warp_split.py into a single windowed exe.
REM  Output: WARP-Split-Console.exe (project root)
REM
REM  IMPORTANT: this file must stay pure ASCII. cmd.exe parses .bat
REM  bytes with the system codepage (GBK/936); UTF-8 Chinese gets
REM  mis-decoded and breaks the command lines.
REM ============================================================
setlocal

set "PY=C:\Users\Administrator\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
set "PIP=C:\Users\Administrator\.workbuddy\binaries\python\envs\default\Scripts\pip.exe"

REM PIP_TARGET is set globally in this machine; packages land in D:\IT\Pythonpip
REM so PYTHONPATH must include it for imports to resolve.
set "PIP_TARGET=D:\IT\Pythonpip"
set "PYTHONPATH=D:\IT\Pythonpip;%PYTHONPATH%"

cd /d "%~dp0"

echo ============================================================
echo  Cloudflare WARP Split Console - Build
echo ============================================================
echo.

REM ---- 1. Check python ----
if not exist "%PY%" (
    echo [ERROR] Python not found: %PY%
    goto :fail
)
"%PY%" -c "import sys; print('Python', sys.version.split()[0])"

REM ---- 2. Ensure PyInstaller ----
"%PY%" -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo [i] Installing PyInstaller ...
    "%PIP%" install pyinstaller
    if errorlevel 1 (
        echo [ERROR] Failed to install PyInstaller
        goto :fail
    )
) else (
    echo [i] PyInstaller already installed
)
echo.

REM ---- 3. Generate icon if missing ----
if not exist "tools\warp.ico" (
    echo [i] Extracting icon from Cloudflare WARP.exe ...
    "%PY%" tools\make_icon.py
)
echo.

REM ---- 4. Clean previous build ----
if exist "dist\WARP-Split-Console.exe" del /f /q "dist\WARP-Split-Console.exe"
if exist "build" rmdir /s /q "build" 2>nul

echo [i] Building single-file exe ...
echo.

"%PY%" -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --name "WARP-Split-Console" ^
    --icon "tools\warp.ico" ^
    --add-data "index.html;." ^
    --add-data "china_cidr.txt;." ^
    --hidden-import "ctypes" ^
    --hidden-import "ctypes.wintypes" ^
    --hidden-import "ipaddress" ^
    --exclude-module "tkinter" ^
    --exclude-module "numpy" ^
    --exclude-module "PIL" ^
    --exclude-module "pytest" ^
    --log-level WARN ^
    warp_split.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed
    goto :fail
)

REM ---- 5. Place exe next to index.html / china_cidr.txt ----
REM APP_DIR is the exe's directory, so keeping it at project root lets
REM settings and rules persist in one place instead of duplicating them.
copy /Y "dist\WARP-Split-Console.exe" "WARP-Split-Console.exe" >nul

echo ============================================================
if not exist "WARP-Split-Console.exe" goto :noexe

echo  [OK] Build succeeded
echo.
echo  Output: WARP-Split-Console.exe
echo.
echo  Usage : double-click it. UAC prompt shows on first launch,
echo          then a tray icon appears and the panel opens at
echo          http://127.0.0.1:8777/
echo ============================================================

endlocal
exit /b 0

:noexe
echo  [ERROR] Build finished but exe was not found.
echo          It may have been quarantined by antivirus.
echo ============================================================
goto :fail

:fail
endlocal
echo.
pause
exit /b 1
