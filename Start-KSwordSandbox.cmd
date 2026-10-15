@echo off
setlocal EnableExtensions

rem Keep the launcher usable when it is started by double-clicking from a release folder.
chcp 65001 >nul 2>&1
set "ROOT=%~dp0"
set "ROOT_READY=0"
set "EXIT_CODE=1"

pushd "%ROOT%" >nul 2>&1
if errorlevel 1 goto :root_error
set "ROOT_READY=1"

echo [KSwordSandbox] 正在启动 WebUI；首次使用时会自动进入设置页面。

if not exist "%ROOT%run.ps1" (
    set "EXIT_CODE=2"
    echo [KSwordSandbox] 错误：找不到根目录 run.ps1。/ Error: root run.ps1 was not found.
    echo [KSwordSandbox] 请从完整发行包目录双击此脚本。/ Start this script from a complete release package.
    goto :finish
)

set "POWERSHELL_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%POWERSHELL_EXE%" (
    set "POWERSHELL_EXE="
    for /f "delims=" %%P in ('where powershell.exe 2^>nul') do if not defined POWERSHELL_EXE set "POWERSHELL_EXE=%%P"
)
if not defined POWERSHELL_EXE (
    set "EXIT_CODE=3"
    echo [KSwordSandbox] 错误：找不到 Windows PowerShell。/ Error: Windows PowerShell was not found.
    echo [KSwordSandbox] 请在 Windows 10 上启用 Windows PowerShell 5.1 后重试。/ Enable Windows PowerShell 5.1 on Windows 10 and retry.
    goto :finish
)

rem -ExecutionPolicy Bypass is scoped to this child process; the host policy is unchanged.
"%POWERSHELL_EXE%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%ROOT%run.ps1" -Mode StartWebUI
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
    echo [KSwordSandbox] WebUI 启动失败（退出码 %EXIT_CODE%）。/ WebUI startup failed (exit code %EXIT_CODE%).
    echo [KSwordSandbox] 请查看上面的错误并按提示修复。/ Review the error above and follow its guidance.
)
goto :finish

:root_error
echo [KSwordSandbox] 错误：无法切换到发行包目录。/ Error: unable to enter the release package directory.
echo [KSwordSandbox] 请把发行包解压到可读写目录后重试。/ Extract the package to a readable and writable directory, then retry.
set "EXIT_CODE=4"

:finish
if "%ROOT_READY%"=="1" popd
if not "%EXIT_CODE%"=="0" (
    echo.
    pause
)
endlocal & exit /b %EXIT_CODE%
