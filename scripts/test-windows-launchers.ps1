param([string]$ServerBinary, [string]$ClientBinary, [string]$PowerShell7)
$ErrorActionPreference = 'Stop'
$Root = Join-Path $env:TEMP ('rdev-launcher-qa-' + [Guid]::NewGuid().ToString('N'))
$ServerProcess = $null
$Children = @()
$OldTemp = $env:TEMP
$OldLocal = $env:LOCALAPPDATA
$OldPath = $env:PATH
$OldCode = $env:RDEV_ENROLLMENT_CODE
$OldUpdate = $env:RDEV_AUTO_UPDATE
function Assert($Ok, $Message) { if (-not $Ok) { throw $Message } }
function Port {
    $L = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $L.Start(); $P = $L.LocalEndpoint.Port; $L.Stop(); return $P
}
function Start-QA($Exe, $Arguments) {
    $Info = New-Object Diagnostics.ProcessStartInfo
    $Info.FileName = $Exe; $Info.Arguments = $Arguments
    $Info.UseShellExecute = $false; $Info.CreateNoWindow = $true
    $Info.RedirectStandardOutput = $true; $Info.RedirectStandardError = $true
    $Process = [Diagnostics.Process]::Start($Info)
    return @{Process=$Process; Out=$Process.StandardOutput.ReadToEndAsync(); Err=$Process.StandardError.ReadToEndAsync()}
}
try {
    New-Item -ItemType Directory -Path $Root | Out-Null
    $Acl = Get-Acl -LiteralPath $Root
    $Acl.SetAccessRuleProtection($true, $false)
    $Sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($Sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl -LiteralPath $Root -AclObject $Acl
    $Static = Join-Path $PSScriptRoot '../internal/server/static'
    foreach ($File in @('run.ps1','run-cmd.ps1')) {
        $Tokens=$null; $Errors=$null
        $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Static $File),[ref]$Tokens,[ref]$Errors)
        Assert ($Errors.Count -eq 0) ('PowerShell parse errors: '+$File)
    }
    $Token = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
    $TokenPath = Join-Path $Root 'control.token'
    [IO.File]::WriteAllText($TokenPath,$Token)
    $Headers=@{'X-RDev-Control-Token'=$Token}
    $Http=Port; $Tcp=Port; $Kcp=Port; $Ssh=Port
    $Base='http://127.0.0.1:'+$Http
    $env:RDEV_CONTROL_TOKEN_FILE=$TokenPath
    $env:RDEV_AUTO_UPDATE='false'
    $ServerProcess=Start-QA $ServerBinary ('--http 127.0.0.1:'+$Http+' --tcp 127.0.0.1:'+$Tcp+' --kcp 127.0.0.1:'+$Kcp+' --ssh 127.0.0.1:'+$Ssh+' --data "'+$Root+'\server" --public-url https://launcher-qa.invalid --no-auto-update')
    $Ready=$false
    for($i=0;$i -lt 40;$i++){try{$null=Invoke-RestMethod ($Base+'/api/config');$Ready=$true;break}catch{Start-Sleep -Milliseconds 250}}
    Assert $Ready 'Server did not start'
    $env:TEMP=Join-Path $Root 'temp'
    $env:LOCALAPPDATA=Join-Path $Root 'local'
    $Cache=Join-Path $env:TEMP 'rdev-cache/go-vqa-windows-amd64-rdev-client-windows-amd64.exe-feidu-20260905-7be947e'
    New-Item -ItemType Directory -Path $Cache,$env:LOCALAPPDATA -Force | Out-Null
    Copy-Item -LiteralPath $ClientBinary -Destination (Join-Path $Cache 'rdev-client-windows-amd64.exe')
    New-Item -ItemType File -Path (Join-Path $Cache '.complete'),(Join-Path $Cache '.runtime-complete') | Out-Null
    # Include spaces and non-ASCII in the actual on-disk launcher path.
    $LaunchDir=Join-Path $Root ('launch ' + [char]0x4e2d + [char]0x6587)
    New-Item -ItemType Directory -Path $LaunchDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $Static 'run.cmd'),(Join-Path $Static 'run-cmd.ps1') -Destination $LaunchDir
    $PS5=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
    $Cases=@(@{Name='CMD-no-PATH';Exe=$env:ComSpec;Cmd=$true},@{Name='PS5.1';Exe=$PS5;Cmd=$false},@{Name='PS7';Exe=$PowerShell7;Cmd=$false})
    foreach($Case in $Cases){
        $env:PATH=$OldPath
        $Invite=Invoke-RestMethod ($Base+'/api/control/enrollments') -Method Post -Headers $Headers -ContentType 'application/json' -Body '{"subject":"launcher-qa","expiresInSeconds":600}'
        $env:RDEV_ENROLLMENT_CODE=$Invite.code
        $Id='launcher-'+$Case.Name
        if($Case.Cmd){
            $env:PATH=''
            $Args='/d /s /c ""'+$LaunchDir+'\run.cmd" -Server '+$Base+' -Version qa -Enroll -Id '+$Id+'"'
        }else{$Args='-NoLogo -NoProfile -File "'+$LaunchDir+'\run-cmd.ps1" -Server '+$Base+' -Version qa -Enroll -Id '+$Id}
        $Child=Start-QA $Case.Exe $Args
        $Children+=$Child
        $Connected=$false
        for($i=0;$i -lt 100;$i++){
            $Clients=@(Invoke-RestMethod ($Base+'/api/clients') -Headers $Headers)
            if(@($Clients|Where-Object {$_.id -eq $Id}).Count -eq 1){$Connected=$true;break}
            if($Child.Process.HasExited){break}
            Start-Sleep -Milliseconds 200
        }
        Assert $Connected ($Case.Name+' did not connect; exit='+$(if($Child.Process.HasExited){$Child.Process.ExitCode}else{'running'}))
        Write-Host ('PASS '+$Case.Name+': real temporary enrollment connected')
    }
    $env:PATH=$OldPath
    $env:RDEV_ENROLLMENT_CODE='invalid'
    $Failure=Start-QA $PS5 ('-NoLogo -NoProfile -File "'+$LaunchDir+'\run-cmd.ps1" -Server '+$Base+' -Version qa -Enroll')
    $Children+=$Failure
    Assert ($Failure.Process.WaitForExit(20000)) 'Failed enrollment hung'
    Assert ($Failure.Process.ExitCode -ne 0) 'Failed enrollment reported success'
    Assert (-not(Test-Path (Join-Path $env:LOCALAPPDATA 'RDev/identity.bin'))) 'Temporary/failed launcher changed persistent identity'
    Write-Host 'PASS failure exit code and no persistent identity changes'
} finally {
    # Kill only clients whose exact executable is beneath this QA root.
    Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -and $_.ExecutablePath.StartsWith($Root+'\')} | ForEach-Object {Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
    foreach($Child in $Children){if(-not $Child.Process.HasExited){$Child.Process.Kill();$Child.Process.WaitForExit()}}
    if($ServerProcess -and -not $ServerProcess.Process.HasExited){$ServerProcess.Process.Kill();$ServerProcess.Process.WaitForExit()}
    $env:TEMP=$OldTemp; $env:LOCALAPPDATA=$OldLocal; $env:PATH=$OldPath; $env:RDEV_ENROLLMENT_CODE=$OldCode; $env:RDEV_AUTO_UPDATE=$OldUpdate
    $env:RDEV_CONTROL_TOKEN_FILE=$null
    if(Test-Path -LiteralPath $Root){
        $Resolved=(Resolve-Path -LiteralPath $Root).Path
        if($Resolved.StartsWith($OldTemp.TrimEnd('\')+'\rdev-launcher-qa-')){Remove-Item -LiteralPath $Resolved -Recurse -Force}
    }
}
