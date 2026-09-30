@echo off
setlocal DisableDelayedExpansion
rem Win7 uses the self-contained client and the built-in certutil downloader.
ver | "%SystemRoot%\System32\find.exe" "6.1." >nul
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
set "RDEV_SERVER=https://r.feidu.fit"
set "RDEV_ENROLL="
set "RDEV_PERSIST="
set "RDEV_IDENTITY="
set "RDEV_ID="
:win7_args
if "%~1"=="" goto :win7_prepare
if /i "%~1"=="-Enroll" (
  set "RDEV_ENROLL=1"
  shift
  goto :win7_args
)
if /i "%~1"=="-Persist" (
  set "RDEV_PERSIST=1"
  shift
  goto :win7_args
)
if /i "%~1"=="-Server" (
  if "%~2"=="" goto :win7_bad_args
  set "RDEV_SERVER=%~2"
  shift
  shift
  goto :win7_args
)
if /i "%~1"=="-IdentityFile" (
  if "%~2"=="" goto :win7_bad_args
  set "RDEV_IDENTITY=%~2"
  shift
  shift
  goto :win7_args
)
if /i "%~1"=="-Id" (
  if "%~2"=="" goto :win7_bad_args
  set "RDEV_ID=%~2"
  shift
  shift
  goto :win7_args
)
:win7_bad_args
echo RDev: unsupported or incomplete Windows 7 option. 1>&2
exit /b 2

:win7_prepare
if not defined RDEV_ENROLL set "RDEV_PERSIST=1"
if "%RDEV_SERVER:~-1%"=="/" set "RDEV_SERVER=%RDEV_SERVER:~0,-1%"
if /i not "%RDEV_SERVER:~0,8%"=="https://" (
  echo RDev: Server must be an HTTPS origin. 1>&2
  exit /b 2
)
set "RDEV_HOME=%LOCALAPPDATA%\RDev"
if not exist "%RDEV_HOME%" mkdir "%RDEV_HOME%" >nul 2>&1
rem Some managed PCs leave an old RDev directory readable but not writable.
rem Probe the directory before downloading; keep the old files and use the
rem current user's roaming profile when the legacy location is locked down.
> "%RDEV_HOME%\.write-test-%RANDOM%" echo ok
if errorlevel 1 (
  set "RDEV_HOME=%APPDATA%\RDev"
  if not exist "%RDEV_HOME%" mkdir "%RDEV_HOME%" >nul 2>&1
  > "%RDEV_HOME%\.write-test-%RANDOM%" echo ok
)
if errorlevel 1 (
  echo RDev: unable to create a writable client directory. 1>&2
  exit /b 1
)
del /q "%RDEV_HOME%\.write-test-*" >nul 2>&1
set "RDEV_SYSTEM=%SystemRoot%\System32"
if defined PROCESSOR_ARCHITEW6432 if exist "%SystemRoot%\Sysnative\certutil.exe" set "RDEV_SYSTEM=%SystemRoot%\Sysnative"
if not exist "%RDEV_SYSTEM%\certutil.exe" (
  echo RDev: certutil is unavailable; unable to verify the Windows 7 client. 1>&2
  exit /b 2
)
set "RDEV_ASSET=rdev-client-windows-win7-rtm-amd64.exe"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" set "RDEV_ASSET=rdev-client-windows-win7-rtm-386.exe"
if /i "%PROCESSOR_ARCHITEW6432%"=="AMD64" set "RDEV_ASSET=rdev-client-windows-win7-rtm-amd64.exe"
set "RDEV_SHA256=081247e2610c9798520691a1bb8dab2bbd7b2e0689ab2f711508af67fb7dab88"
if /i "%RDEV_ASSET%"=="rdev-client-windows-win7-rtm-386.exe" set "RDEV_SHA256=a5643e183ecb9d5104fa9e718391dc8099998421b883331c78cb9acf4bb8a353"
rem Keep this architecture's pinned Win7 build separate from modern clients.
set "RDEV_CLIENT=%RDEV_HOME%\%RDEV_ASSET%"
set "RDEV_ATTEMPT=%RANDOM%-%RANDOM%-%RANDOM%"
set "RDEV_PART=%RDEV_HOME%\download-%RDEV_ATTEMPT%.part"
set "RDEV_HASHFILE=%RDEV_HOME%\hash-%RDEV_ATTEMPT%.txt"
if exist "%RDEV_CLIENT%" (
  call :win7_verify "%RDEV_CLIENT%"
  if not errorlevel 1 goto :win7_enroll
)
del /q "%RDEV_PART%" >nul 2>&1
"%RDEV_SYSTEM%\certutil.exe" -urlcache -split -f "%RDEV_SERVER%/local-release?asset=%RDEV_ASSET%" "%RDEV_PART%" >nul 2>&1
if "%ERRORLEVEL%"=="0" goto :win7_downloaded
rem Stock Win7 cannot negotiate the public HTTPS bootstrap. Only public files
rem use the compatibility endpoint; the complete SHA256 is checked below.
if /i not "%RDEV_SERVER%"=="https://r.feidu.fit" goto :win7_download_failed
del /q "%RDEV_PART%" >nul 2>&1
"%RDEV_SYSTEM%\certutil.exe" -urlcache -split -f "http://r.feidu.fit:18080/local-release?asset=%RDEV_ASSET%" "%RDEV_PART%" >nul 2>&1
if not "%ERRORLEVEL%"=="0" goto :win7_download_failed
:win7_downloaded
call :win7_verify "%RDEV_PART%"
if not "%ERRORLEVEL%"=="0" goto :win7_download_failed
:win7_install
move /y "%RDEV_PART%" "%RDEV_CLIENT%" >nul 2>&1
if not "%ERRORLEVEL%"=="0" goto :win7_download_failed
:win7_enroll
if not defined RDEV_ID set "RDEV_ID=%COMPUTERNAME%"
if not defined RDEV_PERSIST if not defined RDEV_IDENTITY goto :win7_temporary
if not defined RDEV_IDENTITY set "RDEV_IDENTITY=%RDEV_HOME%\identity.bin"
if exist "%RDEV_IDENTITY%" goto :win7_start
if not defined RDEV_ENROLLMENT_CODE goto :win7_missing_code
echo %RDEV_ENROLLMENT_CODE%|"%RDEV_CLIENT%" --server "%RDEV_SERVER%" --id "%RDEV_ID%" --enroll-stdin --enroll-only --identity-file "%RDEV_IDENTITY%" --no-auto-update
if errorlevel 1 (
  echo RDev: enrollment failed. 1>&2
  exit /b 1
)
set "RDEV_ENROLLMENT_CODE="
:win7_start
if not defined RDEV_PERSIST (
  "%RDEV_CLIENT%" --identity-file "%RDEV_IDENTITY%" --no-auto-update
  exit /b
)
set "RDEV_STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
if not exist "%RDEV_STARTUP%" mkdir "%RDEV_STARTUP%" >nul 2>&1
> "%RDEV_STARTUP%\RDev.cmd" echo @start "" /min "%RDEV_CLIENT%" --identity-file "%RDEV_IDENTITY%" --no-auto-update ^>^> "%RDEV_HOME%\client.log" 2^>^&1
if errorlevel 1 (
  echo RDev: unable to configure reconnect after sign-in. 1>&2
  exit /b 1
)
rem ShellExecute creates an independent background process on PowerShell 2.0;
rem CMD start can retain its parent's output pipe and leave the pasted command hung.
"%RDEV_SYSTEM%\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop';try{$p=New-Object Diagnostics.ProcessStartInfo;$p.FileName=$env:RDEV_CLIENT;$p.Arguments='--identity-file '+[char]34+$env:RDEV_IDENTITY+[char]34+' --no-auto-update';$p.UseShellExecute=$true;$p.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden;[Diagnostics.Process]::Start($p)|Out-Null}catch{[Console]::Error.WriteLine('RDev: '+$_.Exception.Message);exit 1}"
if errorlevel 1 (
  echo RDev: unable to start the client. 1>&2
  exit /b 1
)
echo RDev client started. Check its online status in the device page. Reconnect is configured after sign-in.
exit /b 0

:win7_temporary
if not defined RDEV_ENROLLMENT_CODE goto :win7_missing_code
rem Foreground enrollment keeps the identity in memory and creates no startup item.
echo %RDEV_ENROLLMENT_CODE%|"%RDEV_CLIENT%" --server "%RDEV_SERVER%" --id "%RDEV_ID%" --enroll-stdin --no-auto-update
exit /b %ERRORLEVEL%

:win7_missing_code
echo RDev: access configuration is missing. Copy the full command from the device page. 1>&2
exit /b 2

:win7_download_failed
del /q "%RDEV_PART%" "%RDEV_HASHFILE%" >nul 2>&1
echo RDev: client download or SHA-256 verification failed. Check this computer's HTTPS access. 1>&2
exit /b 1

:win7_verify
if not exist "%~1" exit /b 1
"%RDEV_SYSTEM%\certutil.exe" -hashfile "%~1" SHA256 > "%RDEV_HASHFILE%" 2>nul
if not "%ERRORLEVEL%"=="0" (
  del /q "%RDEV_HASHFILE%" >nul 2>&1
  exit /b 1
)
rem Windows 7 prints spaced hex while newer certutil versions do not.
set "RDEV_HASHMATCH="
for /f "usebackq delims=" %%H in ("%RDEV_HASHFILE%") do (
  set "RDEV_HASHLINE=%%H"
  setlocal EnableDelayedExpansion
  if /i "!RDEV_HASHLINE: =!"=="%RDEV_SHA256%" (
    endlocal
    set "RDEV_HASHMATCH=1"
  ) else (
    endlocal
  )
)
del /q "%RDEV_HASHFILE%" >nul 2>&1
if defined RDEV_HASHMATCH exit /b 0
exit /b 1
