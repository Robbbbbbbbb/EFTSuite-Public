@echo off
setlocal enabledelayedexpansion

echo === Stopping EFTHelper / EFTHelper3 ===
taskkill /F /IM EFTHelper.exe 2>nul
taskkill /F /IM EFTHelper2.exe 2>nul
timeout /t 2 /nobreak >nul

echo === Copying source files to Desktop ===
powershell -NoProfile -Command ^
  "$src='C:\Users\azgaming\Downloads\EFTSuite-Public-Testing'; $dst='C:\Users\azgaming\Desktop'; " ^
  "foreach ($f in @('IBscanUltimate.cs','KojakScanner.cs','MainForm.cs','WebSocketServer.cs','Program.cs','LedTestForm.cs','EFTHelper.csproj')) { " ^
  "  $from = Join-Path $src $f; $to = Join-Path $dst $f; " ^
  "  if (Test-Path $from) { Copy-Item $from $to -Force; Write-Host ('  + ' + $f) } " ^
  "  else { Write-Host ('  MISSING: ' + $from) -ForegroundColor Red } }"

echo === Finding MSBuild via vswhere ===
set MSBUILD=
set VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
        if "!MSBUILD!"=="" set "MSBUILD=%%i"
    )
)
if "!MSBUILD!"=="" (
    for /f "tokens=*" %%i in ('where msbuild 2^>nul') do (
        if "!MSBUILD!"=="" set "MSBUILD=%%i"
    )
)
if "!MSBUILD!"=="" (
    echo ERROR: Cannot locate MSBuild.
    pause & exit /b 1
)
echo Found: !MSBUILD!

echo === Building EFTHelper2 (test build with NFIQ2) ===
"!MSBUILD!" "C:\Users\azgaming\Desktop\EFTHelper.csproj" /p:Configuration=Debug /p:Platform=x64 /p:AssemblyName=EFTHelper2 /t:Build /v:minimal

set RESULT=%ERRORLEVEL%
echo === Result: %RESULT% ===
if %RESULT% EQU 0 (
    echo BUILD SUCCESS - C:\Users\azgaming\Desktop\bin\Debug\EFTHelper2.exe
) else (
    echo BUILD FAILED
)
echo %DATE% %TIME% Build result: %RESULT% > "C:\Users\azgaming\Downloads\EFTSuite-Public-Testing\rebuild3_result.txt"
pause
