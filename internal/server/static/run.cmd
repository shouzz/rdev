@echo off
setlocal DisableDelayedExpansion
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
