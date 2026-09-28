# Windows entry point shared by CMD and PowerShell. No credentials are saved.
[CmdletBinding()]
param(
    [Parameter(Position=0)][string]$Server = 'https://r.feidu.fit',
    [string]$Id = '',
    [switch]$Enroll,
    [switch]$Persist,
    [string]$IdentityFile = '',
    [string]$Version = '',
    [string]$Mirror = 'auto'
)
$ErrorActionPreference = 'Stop'
try {
    if ($PSVersionTable.PSVersion -lt [Version]'5.1') {
        throw 'PowerShell 5.1 is required. On Windows 7 SP1 install .NET Framework 4.8 and Windows Management Framework 5.1, then retry. No device was registered.'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    $Base = [Uri]$Server
    if (-not $Base.IsAbsoluteUri -or ($Base.Scheme -ne 'https' -and -not ($Base.Scheme -eq 'http' -and $Base.IsLoopback)) -or $Base.UserInfo -or $Base.Query -or $Base.Fragment -or $Base.AbsolutePath -ne '/') {
        throw 'Server must be an HTTPS origin (HTTP is allowed only for local tests).'
    }
    $Origin = $Base.GetLeftPart([UriPartial]::Authority)
    $Web = New-Object Net.WebClient
    $Web.Encoding = New-Object Text.UTF8Encoding($false)
    try {
        $Source = $Web.DownloadString($Origin + '/run.ps1')
        if (-not $Source -or $Source -notmatch 'function global:RDev') { throw 'Invalid RDev launcher response.' }
        . ([ScriptBlock]::Create($Source))
        $Config = $Web.DownloadString($Origin + '/api/config') | ConvertFrom-Json
    } finally { $Web.Dispose() }
    $TcpPort = [int]$Config.tcpPort
    $KcpPort = [int]$Config.kcpPort
    if ($TcpPort -lt 1 -or $TcpPort -gt 65535 -or $KcpPort -lt 1 -or $KcpPort -gt 65535) { throw 'RDev direct ports are invalid.' }
    $SocketHost = $Base.DnsSafeHost
    if ($Base.HostNameType -eq [UriHostNameType]::IPv6) { $SocketHost = '[' + $SocketHost.Trim('[', ']') + ']' }
    $Options = @{
        Server = 'tcp://' + $SocketHost + ':' + $TcpPort + ',kcp://' + $SocketHost + ':' + $KcpPort + ',' + $Origin
        Id = $Id; IdentityFile = $IdentityFile; Version = $Version; Mirror = $Mirror
        Enroll = [bool]$Enroll; Persist = [bool]($Persist -or -not $Enroll)
    }
    RDev @Options
} catch {
    # Never print the source line: an invocation may contain an enrollment code.
    [Console]::Error.WriteLine('RDev: ' + $_.Exception.Message)
    exit 1
} finally {
    $env:RDEV_ENROLLMENT_CODE = $null
}
