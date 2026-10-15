@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "SCRIPT=%~dp0warp_split.py"
if not exist "%SCRIPT%" (
    echo warp_split.py not found. Please keep run.bat together with the program files.
    pause
    exit /b 1
)

set "PY=C:\Users\Administrator\.workbuddy\binaries\python\versions\3.13.12\python.exe"
if not exist "%PY%" set "PY=python"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$port=8777; $conn=Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue; if($conn){ Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue; Write-Host 'Stopped previous instance on port '$port; Start-Sleep -Seconds 2 }; Start-Process -FilePath '%PY%' -ArgumentList '\"%SCRIPT%\"' -Verb RunAs; $t=0; while($t -lt 30 -and -not (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)){ Start-Sleep -Seconds 1; $t++ }; Start-Process ('http://127.0.0.1:'+$port+'/')"
exit /b 0
