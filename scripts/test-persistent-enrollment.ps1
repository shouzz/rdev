param(
    [Parameter(Mandatory=$true)][string]$ServerBinary,
    [Parameter(Mandatory=$true)][string]$ClientBinary
)
# Windows PowerShell 5.1 integration test with real published clients. Only the
# startup folder and per-installation user directory are redirected into QA.
$ErrorActionPreference = 'Stop'
$OutputEncoding = [Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$ServerBinary = (Resolve-Path -LiteralPath $ServerBinary).Path
$ClientBinary = (Resolve-Path -LiteralPath $ClientBinary).Path
$OriginalTemp = $env:TEMP
$OriginalLocal = $env:LOCALAPPDATA
$OriginalUpdate = $env:RDEV_AUTO_UPDATE
$Root = Join-Path $OriginalTemp ('rdev-enrollment-qa-' + [Guid]::NewGuid().ToString('N'))
$ServerProcess = $null
New-Item -ItemType Directory -Path $Root | Out-Null
$Acl = Get-Acl -LiteralPath $Root
$Acl.SetAccessRuleProtection($true, $false)
$User = [Security.Principal.WindowsIdentity]::GetCurrent().User
$Rule = New-Object Security.AccessControl.FileSystemAccessRule($User, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$Acl.AddAccessRule($Rule)
Set-Acl -LiteralPath $Root -AclObject $Acl
function Assert-QA($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Get-FreePort {
    $Listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $Listener.Start()
    $Port = $Listener.LocalEndpoint.Port
    $Listener.Stop()
    return $Port
}
try {
    $env:RDEV_AUTO_UPDATE = 'false'
    $env:TEMP = Join-Path $Root 'temp'
    New-Item -ItemType Directory -Path $env:TEMP | Out-Null
    $Token = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
    $TokenPath = Join-Path $Root 'control.token'
    [IO.File]::WriteAllText($TokenPath, $Token)
    $Headers = @{'X-RDev-Control-Token'=$Token}
    $HttpPort = Get-FreePort
    $TcpPort = Get-FreePort
    $KcpPort = Get-FreePort
    $SshPort = Get-FreePort
    $Base = 'http://127.0.0.1:' + $HttpPort
    $ServerList = 'tcp://127.0.0.1:' + $TcpPort + ',' + $Base
    $Info = New-Object Diagnostics.ProcessStartInfo
    $Info.FileName = $ServerBinary
    $Info.Arguments = '--http 127.0.0.1:' + $HttpPort + ' --tcp 127.0.0.1:' + $TcpPort + ' --kcp 127.0.0.1:' + $KcpPort + ' --ssh 127.0.0.1:' + $SshPort + ' --data "' + (Join-Path $Root 'server') + '" --public-url https://enrollment-qa.invalid --no-auto-update'
    $Info.UseShellExecute = $false
    $Info.CreateNoWindow = $true
    $Info.EnvironmentVariables['RDEV_CONTROL_TOKEN_FILE'] = $TokenPath
    $Info.RedirectStandardOutput = $true
    $Info.RedirectStandardError = $true
    $ServerProcess = [Diagnostics.Process]::Start($Info)
    $ServerOutput = $ServerProcess.StandardOutput.ReadToEndAsync()
    $ServerError = $ServerProcess.StandardError.ReadToEndAsync()
    $Ready = $false
    for ($i=0; $i -lt 40; $i++) {
        try { $null = Invoke-RestMethod ($Base + '/api/config'); $Ready=$true; break } catch { Start-Sleep -Milliseconds 250 }
    }
    Assert-QA $Ready 'QA server did not become ready'
    . (Join-Path $PSScriptRoot '../internal/server/static/run.ps1')
    function Get-RDevStartupDirectory { return (Join-Path $env:LOCALAPPDATA 'startup') }
    $CacheDir = Join-Path $env:TEMP ('rdev-cache/go-vqa-windows-amd64-rdev-client-windows-amd64.exe-' + $script:LocalClientRevision)
    New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
    Copy-Item -LiteralPath $ClientBinary -Destination (Join-Path $CacheDir 'rdev-client-windows-amd64.exe')
    New-Item -ItemType File -Path (Join-Path $CacheDir '.complete') | Out-Null
    New-Item -ItemType File -Path (Join-Path $CacheDir '.runtime-complete') | Out-Null
    function New-QAInvite([string]$Subject) {
        $Body = @{subject=$Subject; expiresInSeconds=600} | ConvertTo-Json -Compress
        return Invoke-RestMethod ($Base + '/api/control/enrollments') -Method Post -Headers $Headers -ContentType 'application/json' -Body $Body
    }
    function Set-QAMachine([string]$Machine) {
        $env:LOCALAPPDATA = Join-Path $Root $Machine
        New-Item -ItemType Directory -Path (Get-RDevStartupDirectory) -Force | Out-Null
    }
    function Get-QAProcesses {
        return @(Get-CimInstance Win32_Process -Filter "Name = 'rdev-client.exe'" | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($Root + '\') })
    }
    function Wait-QAClients([int]$Count) {
        for ($n=0; $n -lt 60; $n++) {
            $Response = Invoke-RestMethod ($Base + '/api/clients') -Headers $Headers
            $Clients = @($Response)
            if ($Clients.Count -eq $Count) { return $Clients }
            Start-Sleep -Milliseconds 250
        }
        throw "Expected $Count connected QA clients; got $($Clients.Count)"
    }
    $Invites = @()
    foreach ($Machine in @('machine a','machine b','machine c')) {
        Set-QAMachine $Machine
        $Subject = if ($Machine -eq 'machine c') { 'feidu-user:43' } else { 'feidu-user:42' }
        $Invite = New-QAInvite $Subject
        $Invites += $Invite
        Assert-QA ($Invite.code -match '^rdeve_[A-Za-z0-9_-]{43}$') 'QA invitation is malformed'
        $env:RDEV_ENROLLMENT_CODE = $Invite.code
        RDev $ServerList -Version qa -Persist -Id 'SAME-COMPUTER-NAME'
        Assert-QA (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'RDev/identity.bin')) 'No protected identity after enrollment'
        Assert-QA (Test-Path -LiteralPath (Join-Path (Get-RDevStartupDirectory) 'RDev.cmd')) 'No startup entry after enrollment'
        Assert-QA (-not $env:RDEV_ENROLLMENT_CODE) 'Enrollment code remained in environment'
    }
    $Clients = Wait-QAClients 3
    $IDs = @($Clients | ForEach-Object { $_.id } | Sort-Object)
    Assert-QA (($IDs -join ',') -eq 'SAME-COMPUTER-NAME,SAME-COMPUTER-NAME-2,SAME-COMPUTER-NAME-3') 'Same-hostname computers did not get separate IDs'
    Write-Host 'PASS: three independent installs, same/different accounts, all connected with distinct IDs'

    Set-QAMachine 'machine a'
    $IdentityPath = Join-Path $env:LOCALAPPDATA 'RDev/identity.bin'
    $IdentityBefore = [Convert]::ToBase64String([IO.File]::ReadAllBytes($IdentityPath))
    $BeforePids = @((Get-QAProcesses).ProcessId | Sort-Object)
    $Unused = New-QAInvite 'feidu-user:42'
    $env:RDEV_ENROLLMENT_CODE = $Unused.code
    RDev $ServerList -Version qa -Persist -Id 'SAME-COMPUTER-NAME'
    Assert-QA ((@((Get-QAProcesses).ProcessId | Sort-Object) -join ',') -eq ($BeforePids -join ',')) 'Repeat installation restarted or duplicated clients'
    Assert-QA ([Convert]::ToBase64String([IO.File]::ReadAllBytes($IdentityPath)) -eq $IdentityBefore) 'Repeat installation changed identity'
    $Registry = Get-Content -LiteralPath (Join-Path $Root 'server/managed_devices.json') -Raw | ConvertFrom-Json
    $UnusedRecord = @($Registry.enrollments | Where-Object { $_.id -eq $Unused.enrollmentId })
    Assert-QA ($UnusedRecord.Count -eq 1 -and -not $UnusedRecord[0].consumed_at) 'Repeat installation consumed a new invitation'
    Assert-QA (@($Registry.devices).Count -eq 3) 'Repeat installation created another device'
    Write-Host 'PASS: repeat install preserves identity, process IDs, and unused invitation'

    $FirstPath = Join-Path $env:LOCALAPPDATA 'RDev/rdev-client.exe'
    $FirstProcess = @(Get-QAProcesses | Where-Object { $_.ExecutablePath -eq $FirstPath })
    Stop-Process -Id $FirstProcess[0].ProcessId -Force
    $null = Wait-QAClients 2
    $env:RDEV_ENROLLMENT_CODE = $Invites[0].code
    RDev $ServerList -Version qa -Persist -Id 'SAME-COMPUTER-NAME'
    $null = Wait-QAClients 3
    Assert-QA ([Convert]::ToBase64String([IO.File]::ReadAllBytes($IdentityPath)) -eq $IdentityBefore) 'Reconnect changed identity'
    Write-Host 'PASS: stopped client reconnects using saved identity even with a consumed invitation'

    Set-QAMachine 'machine d'
    $env:RDEV_ENROLLMENT_CODE = $Invites[0].code
    RDev $ServerList -Version qa -Persist -Id 'SAME-COMPUTER-NAME'
    Assert-QA (-not (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'RDev/identity.bin'))) 'Consumed invitation unexpectedly created identity'
    Assert-QA (-not (Test-Path -LiteralPath (Join-Path (Get-RDevStartupDirectory) 'RDev.cmd'))) 'Failed enrollment installed startup entry'
    $null = Wait-QAClients 3
    Write-Host 'PASS: consumed invitation on a new computer fails cleanly without disrupting existing computers'
    Write-Host ('PASS: real persistent launcher integration on PowerShell ' + $PSVersionTable.PSVersion)
} finally {
    Get-CimInstance Win32_Process -Filter "Name = 'rdev-client.exe'" | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($Root + '\') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    if ($ServerProcess -and -not $ServerProcess.HasExited) { $ServerProcess.Kill(); $ServerProcess.WaitForExit() }
    $env:TEMP = $OriginalTemp
    $env:LOCALAPPDATA = $OriginalLocal
    $env:RDEV_AUTO_UPDATE = $OriginalUpdate
    $env:RDEV_ENROLLMENT_CODE = $null
    $Headers=$null; $Token=$null; $Invites=$null; $Invite=$null; $Unused=$null; $Registry=$null
    $Resolved = (Resolve-Path -LiteralPath $Root).Path
    if ($Resolved.StartsWith($OriginalTemp.TrimEnd('\') + '\rdev-enrollment-qa-')) {
        Remove-Item -LiteralPath $Resolved -Recurse -Force
    }
}
