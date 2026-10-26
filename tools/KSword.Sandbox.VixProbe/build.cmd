@echo off
setlocal EnableExtensions EnableDelayedExpansion

for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
if not defined VIX_SDK_ROOT set "VIX_SDK_ROOT=%ProgramFiles(x86)%\VMware\VMware VIX"
if not defined VIX_OUT_DIR set "VIX_OUT_DIR=%REPO_ROOT%\artifacts\_build\vix-probe"

if not exist "%VIX_SDK_ROOT%\vix.h" (
  echo VMware VIX SDK header missing: "%VIX_SDK_ROOT%\vix.h" 1>&2
  exit /b 2
)
if not exist "%VIX_SDK_ROOT%\Vix64AllProducts.lib" (
  echo VMware VIX SDK library missing: "%VIX_SDK_ROOT%\Vix64AllProducts.lib" 1>&2
  exit /b 2
)

where cl.exe >nul 2>nul
if errorlevel 1 (
  if not defined VSINSTALLDIR (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if not exist "!VSWHERE!" (
      echo Visual Studio C++ toolchain or vswhere.exe is missing. 1>&2
      exit /b 2
    )
    for /f "usebackq tokens=*" %%I in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALLDIR=%%I\"
  )
  if not exist "!VSINSTALLDIR!VC\Auxiliary\Build\vcvars64.bat" (
    echo Visual Studio vcvars64.bat is missing. 1>&2
    exit /b 2
  )
  call "!VSINSTALLDIR!VC\Auxiliary\Build\vcvars64.bat" >nul
  if errorlevel 1 exit /b 2
)

if not exist "%VIX_OUT_DIR%" mkdir "%VIX_OUT_DIR%"
if errorlevel 1 exit /b 2

cl /nologo /W4 /EHsc /MT /I "%VIX_SDK_ROOT%" ^
  /Fo"%VIX_OUT_DIR%\vix_probe.obj" /Fe"%VIX_OUT_DIR%\vix_probe.exe" ^
  "%~dp0vix_probe.cpp" "%VIX_SDK_ROOT%\Vix64AllProducts.lib" ^
  kernel32.lib user32.lib advapi32.lib ole32.lib oleaut32.lib ws2_32.lib shell32.lib ^
  /link /INCREMENTAL:no /NODEFAULTLIB:libcmt.lib
exit /b %errorlevel%
