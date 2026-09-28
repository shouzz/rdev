@echo off
setlocal DisableDelayedExpansion
rem Win7 path: use the self-contained Go client and BITS. No PowerShell,
rem .NET 4.8, WMF, JSON parser, or machine policy change is required.
ver | find "6.1." >nul
if not errorlevel 1 goto :win7
set "RDEV_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if defined PROCESSOR_ARCHITEW6432 if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "RDEV_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%RDEV_PS%" (
  echo RDev: Windows PowerShell is missing. Repair Windows PowerShell before retrying. 1>&2
  exit /b 2
)
if exist "%~dp0run-cmd.ps1" (
  "%RDEV_PS%" -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0run-cmd.ps1" %*
  exit /b
)
set "RDEV_ENTRY=%TEMP%\rdev-launch-%RANDOM%-%RANDOM%-%RANDOM%.ps1"
"%RDEV_PS%" -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop';$f=$null;try{if($PSVersionTable.PSVersion -lt [Version]'5.1'){throw 'Install .NET Framework 4.8 and Windows Management Framework 5.1 on Windows 7 SP1 first.'};[Net.ServicePointManager]::SecurityProtocol=[Enum]::ToObject([Net.SecurityProtocolType],3072);$f=[IO.File]::Open($env:RDEV_ENTRY,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$w=New-Object Net.WebClient;try{$b=$w.DownloadData('https://r.feidu.fit/run-cmd.ps1')}finally{$w.Dispose()};if($b.Length -lt 100){throw 'Launcher response is empty'};$f.Write($b,0,$b.Length);$f.Dispose();$f=$null}catch{if($f){$f.Dispose();[IO.File]::Delete($env:RDEV_ENTRY)};[Console]::Error.WriteLine('RDev: '+$_.Exception.Message);exit 1}"
if errorlevel 1 exit /b 1
rem Process-scoped policy; does not change the machine or override Group Policy.
"%RDEV_PS%" -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File "%RDEV_ENTRY%" %*
set "RDEV_EXIT=%ERRORLEVEL%"
del /q "%RDEV_ENTRY%" >nul 2>&1
exit /b %RDEV_EXIT%

:win7
set "RDEV_HOME=%LOCALAPPDATA%\RDev"
if not exist "%RDEV_HOME%" mkdir "%RDEV_HOME%" >nul 2>&1
set "RDEV_ASSET=rdev-client-windows-win7-amd64.exe"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" set "RDEV_ASSET=rdev-client-windows-win7-386.exe"
if /i "%PROCESSOR_ARCHITEW6432%"=="AMD64" set "RDEV_ASSET=rdev-client-windows-win7-amd64.exe"
set "RDEV_CLIENT=%RDEV_HOME%\rdev-client.exe"
if not exist "%RDEV_CLIENT%" (
  where bitsadmin >nul 2>&1
  if errorlevel 1 (
    echo RDev: Windows 7 BITS is unavailable. 1>&2
    exit /b 2
  )
  bitsadmin /reset >nul 2>&1
  bitsadmin /transfer RDevClient /download /priority FOREGROUND "https://r.feidu.fit/local-release?asset=%RDEV_ASSET%" "%RDEV_CLIENT%" >nul
  if errorlevel 1 (
    echo RDev: client download failed. Check Windows 7 SP1 updates and network access. 1>&2
    exit /b 1
  )
)
if not exist "%RDEV_CLIENT%" (
  echo RDev: client download produced no file. 1>&2
  exit /b 1
)
set "RDEV_IDENTITY=%RDEV_HOME%\identity.bin"
if exist "%RDEV_IDENTITY%" goto :win7_start
set /p "RDEV_CODE=Paste the device code: "
if not defined RDEV_CODE (
  echo RDev: device code is required. 1>&2
  exit /b 2
)
echo %RDEV_CODE%|"%RDEV_CLIENT%" --server https://r.feidu.fit --enroll-stdin --enroll-only --identity-file "%RDEV_IDENTITY%"
if errorlevel 1 (
  echo RDev: enrollment failed. 1>&2
  exit /b 1
)
:win7_start
if not exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" mkdir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" >nul 2>&1
> "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\RDev.cmd" echo @start "" /min "%RDEV_CLIENT%" --identity-file "%RDEV_IDENTITY%"
start "" /min "%RDEV_CLIENT%" --identity-file "%RDEV_IDENTITY%"
echo RDev is connected. It will reconnect after sign-in.
exit /b 0
