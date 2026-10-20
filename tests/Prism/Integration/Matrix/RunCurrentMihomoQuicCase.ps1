#requires -Version 7.4
[CmdletBinding()]
param(
    [string]$PrismTemplate = '',
    [Parameter(Mandatory = $true)][string]$MihomoTemplate,
    [Parameter(Mandatory = $true)][ValidateSet('hysteria2', 'tuic')][string]$Protocol,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,48}$')]
    [string]$CaseDirectory,
    [ValidateRange(0, 65535)][int]$TcpPort = 0,
    [ValidateRange(0, 65535)][int]$QuicPort = 0,
    [ValidateRange(0, 65535)][int]$TargetPort = 0,
    [ValidateRange(0, 65535)][int]$ProxyPort = 0,
    [string]$MihomoExecutable = 'mihomo.exe',
    [ValidateRange(1, 2147483647)][int]$RepeatCount = 3
)

if ($PSVersionTable.PSVersion -lt [Version]'7.4') {
    throw 'Mihomo interop runners require PowerShell 7.4 or newer'
}
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'MihomoTestSupport.ps1')

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)

    $Path = Get-MihomoCaseArtifactPath $script:CaseDirectory $Path
    $Encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [System.IO.File]::WriteAllText($Path, $Content, $Encoding)
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToUpperInvariant()
}

function Get-Sha256Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $Hasher = [System.Security.Cryptography.SHA256]::Create()
    $Digest = $null
    try {
        $Digest = $Hasher.ComputeHash($Bytes)
        return [Convert]::ToHexString($Digest).ToUpperInvariant()
    }
    finally {
        if ($null -ne $Digest) {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($Digest)
        }
        $Hasher.Dispose()
    }
}

function Resolve-QuicMihomoTemplatePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$TemplateDirectory
    )

    $FullPath = [System.IO.Path]::GetFullPath($Path)
    $MatrixDirectory = [System.IO.Path]::GetFullPath($TemplateDirectory)
    $AllowedPaths = @(
        [System.IO.Path]::GetFullPath((Join-Path $MatrixDirectory 'QuicHysteria2Mihomo.yaml')),
        [System.IO.Path]::GetFullPath((Join-Path $MatrixDirectory 'QuicTuicMihomo.yaml'))
    )
    $Allowed = $false
    foreach ($AllowedPath in $AllowedPaths) {
        if ([string]::Equals($FullPath, $AllowedPath,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            $Allowed = $true
            break
        }
    }
    if (-not $Allowed) {
        throw 'QUIC Mihomo template must be one of the checked-in Matrix fixtures'
    }
    $FullPath = Assert-MihomoLocalFixedFilePath $FullPath
    $FullPath = [System.IO.Path]::GetFullPath($FullPath)
    return $FullPath
}

function Get-FreeLoopbackPort {
    param([int[]]$AvoidPorts = @())

    for ($Attempt = 0; $Attempt -lt 64; $Attempt++) {
        $Listener = [System.Net.Sockets.TcpListener]::new(
            [System.Net.IPAddress]::Loopback, 0)
        $Udp = $null
        try {
            $Listener.Start()
            $Port = ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port
            if ($Port -in $AvoidPorts) {
                continue
            }
            $UdpEndpoint = [System.Net.IPEndPoint]::new(
                [System.Net.IPAddress]::Loopback, $Port)
            $Udp = [System.Net.Sockets.UdpClient]::new($UdpEndpoint)
            $UdpPort = ([System.Net.IPEndPoint]$Udp.Client.LocalEndPoint).Port
            if ($UdpPort -ne $Port) {
                throw 'UDP port probe bound an unexpected local port'
            }
            return $UdpPort
        }
        catch {
            if ($Attempt -eq 63) {
                throw
            }
        }
        finally {
            if ($null -ne $Udp) {
                $Udp.Dispose()
            }
            $Listener.Stop()
        }
    }
    throw 'Unable to reserve a loopback TCP/UDP port'
}

function Read-QuicLogDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string]$LogRoot
    )

    $Path = Join-Path $LogRoot 'prism.log'
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Available = $false; Path = $Path; Excerpt = '' }
    }
    try {
        $Excerpt = (@(Get-Content -LiteralPath $Path -Tail 3 -ErrorAction Stop) -join "`n")
    } catch {
        return [pscustomobject]@{ Available = $false; Path = $Path; Excerpt = '' }
    }
    if ($Excerpt.Length -gt 4096) {
        $Excerpt = $Excerpt.Substring($Excerpt.Length - 4096)
    }
    return [pscustomobject]@{ Available = $true; Path = $Path; Excerpt = $Excerpt }
}

function Get-QuicCurlProxyEndpoint {
    param(
        [Parameter(Mandatory = $true)][psobject]$CurlOwner,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ProxyPort
    )

    if (-not (Test-MihomoOwnedProcessIdentity $CurlOwner)) {
        return $null
    }
    try {
        $Connections = @(Get-NetTCPConnection -OwningProcess $CurlOwner.Id `
            -RemotePort $ProxyPort -ErrorAction Stop)
    }
    catch {
        throw 'Unable to inspect the owned curl TCP connection'
    }

    $Endpoints = [System.Collections.Generic.List[object]]::new()
    foreach ($Connection in $Connections) {
        if ($Connection.State -notin @(
                'Established', 'CloseWait', 'FinWait1', 'FinWait2', 'Closing', 'LastAck') -or
            -not (Test-MihomoAddressMatchesExpectedLoopback `
                ([string]$Connection.RemoteAddress) '127.0.0.1') -or
            -not (Test-MihomoAddressMatchesExpectedLoopback `
                ([string]$Connection.LocalAddress) '127.0.0.1')) {
            continue
        }
        $Address = $null
        $Port = 0
        $RemoteAddress = $null
        $RemotePortValue = 0
        if (-not [System.Net.IPAddress]::TryParse(
                [string]$Connection.LocalAddress, [ref]$Address) -or
            -not [int]::TryParse([string]$Connection.LocalPort, [ref]$Port) -or
            -not [System.Net.IPAddress]::TryParse(
                [string]$Connection.RemoteAddress, [ref]$RemoteAddress) -or
            -not [int]::TryParse([string]$Connection.RemotePort, [ref]$RemotePortValue) -or
            $Port -lt 1 -or $Port -gt 65535 -or
            $RemotePortValue -ne $ProxyPort) {
            continue
        }
        if ($Address.IsIPv4MappedToIPv6) {
            $Address = $Address.MapToIPv4()
        }
        if ($RemoteAddress.IsIPv4MappedToIPv6) {
            $RemoteAddress = $RemoteAddress.MapToIPv4()
        }
        [void]$Endpoints.Add([pscustomobject]@{
            Address = $Address.ToString()
            Port = $Port
            RemoteAddress = $RemoteAddress.ToString()
            RemotePort = $RemotePortValue
        })
    }
    if ($Endpoints.Count -gt 1) {
        throw 'The owned curl process has multiple active TCP connections to its proxy port'
    }
    if (-not (Test-MihomoOwnedProcessIdentity $CurlOwner)) {
        return $null
    }
    if ($Endpoints.Count -eq 1) {
        return $Endpoints[0]
    }
    return $null
}

function Get-QuicConnectionEvidenceForCurl {
    param(
        [Parameter(Mandatory = $true)][psobject]$Connection,
        [Parameter(Mandatory = $true)][psobject]$RequestEvidence
    )

    $Metadata = $Connection.PSObject.Properties['metadata']
    if ($null -eq $Metadata) {
        return $null
    }
    $SourceAddressProperty = $Metadata.Value.PSObject.Properties['sourceIP']
    $SourcePortProperty = $Metadata.Value.PSObject.Properties['sourcePort']
    if ($null -eq $SourceAddressProperty -or $null -eq $SourcePortProperty) {
        return $null
    }
    $SourceAddress = $null
    $ExpectedSourceAddress = $null
    $SourcePort = 0
    if (-not [System.Net.IPAddress]::TryParse(
            [string]$SourceAddressProperty.Value, [ref]$SourceAddress) -or
        -not [System.Net.IPAddress]::TryParse(
            [string]$RequestEvidence.SourceAddress, [ref]$ExpectedSourceAddress) -or
        -not [int]::TryParse([string]$SourcePortProperty.Value, [ref]$SourcePort) -or
        $SourcePort -lt 1 -or $SourcePort -gt 65535) {
        return $null
    }
    if ($SourceAddress.IsIPv4MappedToIPv6) {
        $SourceAddress = $SourceAddress.MapToIPv4()
    }
    if ($ExpectedSourceAddress.IsIPv4MappedToIPv6) {
        $ExpectedSourceAddress = $ExpectedSourceAddress.MapToIPv4()
    }
    if (-not $SourceAddress.Equals($ExpectedSourceAddress) -or
        $SourcePort -ne $RequestEvidence.SourcePort) {
        return $null
    }

    $ConnectionId = $Connection.PSObject.Properties['id']
    if ($null -eq $ConnectionId -or $ConnectionId.Value -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$ConnectionId.Value)) {
        throw 'The curl-matched Mihomo connection has no unique connection id'
    }
    $Route = Get-MihomoConnectionRouteEvidence $Connection `
        $RequestEvidence.TargetAddress $RequestEvidence.TargetPort `
        $RequestEvidence.InboundPort $RequestEvidence.Network `
        $RequestEvidence.ExpectedRoute $RequestEvidence.ExpectedChain
    return [pscustomobject]@{
        ConnectionId = [string]$ConnectionId.Value
        SourceAddress = $SourceAddress.ToString()
        SourcePort = $SourcePort
        Evidence = $Route
    }
}

$RepositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..\..\..'))
Assert-MihomoLocalFixedDirectoryPath $RepositoryRoot
if ($TcpPort -eq 0) {
    $TcpPort = Get-FreeLoopbackPort
}
if ($QuicPort -eq 0) {
    $QuicPort = Get-FreeLoopbackPort @($TcpPort)
}
if ($TargetPort -eq 0) {
    $TargetPort = Get-FreeLoopbackPort @($TcpPort, $QuicPort)
}
if ($ProxyPort -eq 0) {
    $ProxyPort = Get-FreeLoopbackPort @($TcpPort, $QuicPort, $TargetPort)
}
$RequiredPorts = @($TcpPort, $QuicPort, $TargetPort, $ProxyPort)
if (@($RequiredPorts | Where-Object { $_ -lt 1 }).Count -gt 0 -or
    @($RequiredPorts | Select-Object -Unique).Count -ne $RequiredPorts.Count) {
    throw 'QUIC test listener, proxy, and target ports must be positive and distinct'
}
$NextAutoPort = 65535
function Get-NextLoopbackPort {
    param([int[]]$AvoidPorts = @())

    while ($script:NextAutoPort -ge 1) {
        $Candidate = $script:NextAutoPort
        $script:NextAutoPort--
        if ($Candidate -in $AvoidPorts) {
            continue
        }
        $Listener = [System.Net.Sockets.TcpListener]::new(
            [System.Net.IPAddress]::Loopback, $Candidate)
        $Udp = $null
        try {
            $Listener.Start()
            $Udp = [System.Net.Sockets.UdpClient]::new(
                [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Candidate))
            return $Candidate
        }
        catch {
            continue
        }
        finally {
            if ($null -ne $Udp) {
                $Udp.Dispose()
            }
            $Listener.Stop()
        }
    }
    throw 'Unable to reserve a distinct loopback TCP/UDP port for this QUIC case'
}
$CaseDirectory = New-UniqueMihomoCaseDirectory $CaseDirectory
$TargetRoot = Join-Path $CaseDirectory 'target-root'
$PrismLogRoot = Join-Path $CaseDirectory 'prism-logs'
$PrismConfig = Join-Path $CaseDirectory 'prism.json'
$GeneratedPrismProfile = [string]::IsNullOrWhiteSpace($PrismTemplate)
$GeneratedCertificatePath = Join-Path $CaseDirectory 'mihomo-quic-cert.pem'
$GeneratedPrivateKeyPath = Join-Path $CaseDirectory 'mihomo-quic-key.pem'
$Started = [System.Collections.Generic.List[object]]::new()
$TemporaryDirectories = [System.Collections.Generic.List[string]]::new()
$TargetProcess = $null
$TargetProcessOwner = $null
$PrismProcess = $null
$PrismProcessOwner = $null
$Results = [System.Collections.Generic.List[object]]::new()
$CleanupFailures = [System.Collections.Generic.List[string]]::new()
$SensitiveValues = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$UsedProxyPorts = [System.Collections.Generic.HashSet[int]]::new()
$UsedControllerPorts = [System.Collections.Generic.HashSet[int]]::new()
$AttemptControllerSecret = ''
try {
$PrismExecutable = Assert-MihomoLocalFixedFilePath (
    Join-Path $RepositoryRoot 'build/src/Prism.exe')
$MihomoExecutable = Resolve-MihomoExecutable $MihomoExecutable
$CurlExecutable = Resolve-MihomoExecutablePath 'curl.exe'
$FileServerExecutable = Assert-MihomoLocalFixedFilePath (
    Join-Path $RepositoryRoot 'build/tests/PrismMatrixFileServer.exe')
$PrismSha256 = Get-Sha256 $PrismExecutable
$MihomoSha256 = Get-Sha256 $MihomoExecutable
$TargetRoot = New-MihomoCaseSubdirectory $CaseDirectory 'target-root'
$PrismLogRoot = New-MihomoCaseSubdirectory $CaseDirectory 'prism-logs'
$ResponsePattern = [System.Text.Encoding]::UTF8.GetBytes('prism-quic-response')
$TargetResponseBytes = [byte[]]::new(1MB)
for ($Offset = 0; $Offset -lt $TargetResponseBytes.Length; $Offset += $ResponsePattern.Length) {
    $CopyCount = [Math]::Min($ResponsePattern.Length, $TargetResponseBytes.Length - $Offset)
    [Array]::Copy($ResponsePattern, 0, $TargetResponseBytes, $Offset, $CopyCount)
}
$TargetResponsePath = Join-Path $TargetRoot 'hello.txt'
$TargetResponsePath = Get-MihomoCaseArtifactPath $CaseDirectory $TargetResponsePath
[System.IO.File]::WriteAllBytes($TargetResponsePath, $TargetResponseBytes)
$TargetResponsePath = Get-MihomoCaseArtifactPath $CaseDirectory $TargetResponsePath
$ExpectedTargetResponse = [System.IO.File]::ReadAllBytes($TargetResponsePath)

$GeneratedCredential = ''
$GeneratedUuid = ''
$QuicSecretReference = ''
if ($GeneratedPrismProfile) {
    $PrismTemplatePath = Assert-MihomoLocalFixedFilePath (
        Join-Path $RepositoryRoot 'Include/Prism/Application/Configuration/PrismConfiguration.json')
    $PrismObject = Read-MihomoCasePrismConfiguration $PrismTemplatePath
    $GeneratedCredential = New-MihomoControllerSecret
    $QuicSecretReference = 'mihomo-quic-' + $Protocol
    if ($Protocol -eq 'tuic') {
        $GeneratedUuid = New-MihomoUuid
    }
    if ($null -eq $PrismObject.PSObject.Properties['Secrets']) {
        $PrismObject | Add-Member -NotePropertyName Secrets -NotePropertyValue ([ordered]@{})
    } else {
        $PrismObject.Secrets = [ordered]@{}
    }
    $PrismObject.Secrets[$QuicSecretReference] = $GeneratedCredential
    if (@($PrismObject.Accounts).Count -ne 1) {
        throw 'Default Prism configuration must have one account for the isolated QUIC fixture'
    }
    $PrismObject.Accounts[0].SecretRef = $QuicSecretReference
    $PrismObject.Accounts[0].Credential = ''
    if ($null -eq $PrismObject.Accounts[0].PSObject.Properties['Credentials']) {
        $PrismObject.Accounts[0] | Add-Member -NotePropertyName Credentials `
            -NotePropertyValue ([ordered]@{})
    } else {
        $PrismObject.Accounts[0].Credentials = [ordered]@{}
    }
    $PrismObject.Protocols = @([pscustomobject]@{
            Id = 'protocol-' + $Protocol; Name = $Protocol; Builtin = $Protocol; Requires = @()
            Quic = [pscustomobject]@{
                Alpn = 'h3'; ServerName = 'localhost'; CredentialSecretRef = $QuicSecretReference
                MaxStreams = 64; MaxDatagrams = 64; Uuid = $GeneratedUuid
            }
        })
    $PrismObject.NativeTls.Enabled = $true
    $PrismObject.NativeTls.CertificateFile = $GeneratedCertificatePath
    $PrismObject.NativeTls.PrivateKeyFile = $GeneratedPrivateKeyPath
    New-MihomoQuicCertificate $CaseDirectory $GeneratedCertificatePath $GeneratedPrivateKeyPath
}
else {
    $PrismTemplatePath = Assert-MihomoLocalFixedFilePath $PrismTemplate
    $PrismTemplateDirectory = Split-Path -Parent $PrismTemplatePath
    $PrismObject = Read-MihomoCasePrismConfiguration $PrismTemplatePath
    if (-not [bool]$PrismObject.NativeTls.Enabled) {
        throw 'Prism QUIC template must enable NativeTls for its case certificate'
    }
    $PrismObject.NativeTls.CertificateFile = Resolve-MihomoTemplatePath `
        ([string]$PrismObject.NativeTls.CertificateFile) $PrismTemplateDirectory
    $PrismObject.NativeTls.PrivateKeyFile = Resolve-MihomoTemplatePath `
        ([string]$PrismObject.NativeTls.PrivateKeyFile) $PrismTemplateDirectory
    if (-not (Test-Path -LiteralPath $PrismObject.NativeTls.CertificateFile -PathType Leaf) -or
        -not (Test-Path -LiteralPath $PrismObject.NativeTls.PrivateKeyFile -PathType Leaf)) {
        throw 'Prism template NativeTls certificate and private key must exist'
    }
}
if ($GeneratedPrismProfile) {
    $PrismTemplateDirectory = Split-Path -Parent $PrismTemplatePath
}
$PrismObject.Operations.WebDirectory = ''
Resolve-MihomoPrismLocalPaths $PrismObject $PrismTemplateDirectory
foreach ($SensitiveValue in @(Get-MihomoConfigurationSensitiveValues $PrismObject)) {
    [void]$SensitiveValues.Add($SensitiveValue)
}
$PrismObject.Protocols = @($PrismObject.Protocols |
        Where-Object { $_.Id -eq ('protocol-' + $Protocol) })
if ($PrismObject.Protocols.Count -ne 1) {
    throw "Prism template must define exactly one protocol-$Protocol entry"
}
$PrismObject.Protocols += [pscustomobject]@{
    Id = 'protocol-http'; Name = 'http'; Builtin = 'http'; Requires = @()
}
$PrismObject.Carriers = @()
$PrismObject.ProtocolBindings = @(
    [pscustomobject]@{
        Id = 'binding-http'; ProtocolId = 'protocol-http'; TcpEnabled = $true
        UdpEnabled = $false; MuxModes = @(); Priority = 0
        Recognition = [pscustomobject]@{}
    },
    [pscustomobject]@{
        Id = 'binding-' + $Protocol; ProtocolId = 'protocol-' + $Protocol
        TcpEnabled = $false; UdpEnabled = $true; MuxModes = @(); Priority = 100
        Recognition = [pscustomobject]@{}
    })
Set-MihomoPrismDialCarrierBackend $PrismObject 0
Set-MihomoPrismQuicListeners $PrismObject $TcpPort $QuicPort
$PrismObject.Logging.Directory = $PrismLogRoot.Replace('\', '/')
$PrismObject.Logging.FileName = 'prism.log'
$PrismOperationsPort = Get-FreeLoopbackPort @($TcpPort, $QuicPort, $TargetPort, $ProxyPort)
$PrismObject.Operations.Enabled = $false
$PrismObject.Operations.Endpoint = "127.0.0.1:$PrismOperationsPort"

$MihomoTemplatePath = Resolve-QuicMihomoTemplatePath $MihomoTemplate $PSScriptRoot
$MihomoTemplateBytes = [System.IO.File]::ReadAllBytes($MihomoTemplatePath)
$MihomoTemplateSha256 = Get-Sha256Bytes $MihomoTemplateBytes
$PinnedTemplateSha256 = if ($Protocol -eq 'hysteria2') {
    'F28C742A2CD0BFCF9A64294FADE23D0D1DE80BCB5DE6F4CFD5560DB24948558E'
} else {
    '91314C01451CD162553F7A9239856075BFB72AA4086CD54ECD2635735DFCDB5D'
}
if ($MihomoTemplateSha256 -cne $PinnedTemplateSha256) {
    throw 'QUIC Mihomo template bytes do not match the pinned protocol fixture'
}
$Yaml = [System.Text.UTF8Encoding]::new($false, $true).GetString($MihomoTemplateBytes)
Assert-MihomoYamlSupportedSyntax $Yaml
Assert-MihomoNoShortcutInbounds $Yaml
Assert-MihomoTemplateProxyEndpointsAreLoopback $Yaml
if (Test-MihomoYamlContainsKey $Yaml @('proxy-providers', 'rule-providers') -TopLevelOnly) {
    throw 'QUIC template cannot use remote provider sections'
}
foreach ($SensitiveValue in @(Get-MihomoYamlSensitiveValues $Yaml)) {
    [void]$SensitiveValues.Add($SensitiveValue)
}
$Yaml = Remove-MihomoYamlComments $Yaml
$Yaml = Normalize-MihomoCaseNetworkConfiguration $Yaml
$ActiveProxy = if ($Protocol -eq 'hysteria2') { 'Hysteria2 QUIC' } else { 'TUIC v5 QUIC' }
$SelectedProxy = Assert-MihomoQuicRoute `
    $Yaml $Protocol $ActiveProxy 'PrismPreview-Active' -AllowPlaceholder
$QuicProtocolConfiguration = @($PrismObject.Protocols |
    Where-Object { $_.Id -eq ('protocol-' + $Protocol) })[0]
$PrismAlpn = [string]$QuicProtocolConfiguration.Quic.Alpn
Assert-MihomoQuicProxyAlpn $Yaml $SelectedProxy $PrismAlpn
if ($GeneratedPrismProfile) {
    $Yaml = Set-MihomoProxyScalar $Yaml $SelectedProxy 'password' $GeneratedCredential
    if ($Protocol -eq 'tuic') {
        $Yaml = Set-MihomoProxyScalar $Yaml $SelectedProxy 'uuid' $GeneratedUuid
    }
    $Yaml = Set-MihomoProxyScalar $Yaml $SelectedProxy 'sni' 'localhost'
    $Yaml = Set-MihomoProxyScalar $Yaml $SelectedProxy 'skip-cert-verify' 'true'
}
$TemplateQuicSecretReference = [string]$QuicProtocolConfiguration.Quic.CredentialSecretRef
if (-not $GeneratedPrismProfile) {
    $QuicSecretReference = 'mihomo-quic-' + $Protocol
}
$PrismSecretProperty = $PrismObject.PSObject.Properties['Secrets']
if ($null -eq $PrismSecretProperty) {
    throw 'Prism QUIC configuration must include its resolved credential in the case configuration'
}
$PrismCredential = ''
if ($PrismObject.Secrets -is [System.Collections.IDictionary]) {
    if ($PrismObject.Secrets.Contains($TemplateQuicSecretReference)) {
        $PrismCredential = [string]$PrismObject.Secrets[$TemplateQuicSecretReference]
    }
}
else {
    $SecretProperty = $PrismObject.Secrets.PSObject.Properties[$TemplateQuicSecretReference]
    if ($null -ne $SecretProperty) {
        $PrismCredential = [string]$SecretProperty.Value
    }
}
$MihomoCredential = Get-MihomoProxyScalar $Yaml $SelectedProxy 'password'
if ([string]::IsNullOrEmpty($PrismCredential) -or
    -not [string]::Equals($PrismCredential, $MihomoCredential, [System.StringComparison]::Ordinal)) {
    throw 'Prism and Mihomo QUIC credential fixtures do not match'
}
if (-not $GeneratedPrismProfile) {
    Reduce-MihomoPrismConfigurationToQuicAccount `
        $PrismObject ('protocol-' + $Protocol) $TemplateQuicSecretReference `
        $QuicSecretReference $PrismCredential
}
$MihomoServerName = Get-MihomoProxyScalar $Yaml $SelectedProxy 'sni'
if (-not [string]::Equals($MihomoServerName, [string]$QuicProtocolConfiguration.Quic.ServerName,
        [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Prism and Mihomo QUIC server-name settings do not match'
}
if ($Protocol -eq 'tuic') {
    $MihomoUuid = Get-MihomoProxyScalar $Yaml $SelectedProxy 'uuid'
    if (-not [string]::Equals($MihomoUuid, [string]$QuicProtocolConfiguration.Quic.Uuid,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Prism and Mihomo TUIC UUID settings do not match'
    }
    $DisableSniText = Get-MihomoOptionalProxyScalar $Yaml $SelectedProxy 'disable-sni'
    $MihomoDisablesSni = $false
    if ($null -ne $DisableSniText -and
        (-not [bool]::TryParse($DisableSniText, [ref]$MihomoDisablesSni) -or
            $MihomoDisablesSni)) {
        throw 'Selected Mihomo TUIC proxy must not disable server-name indication'
    }
}
$MihomoSkipCertVerifyText = Get-MihomoProxyScalar $Yaml $SelectedProxy 'skip-cert-verify'
$MihomoSkipsCertVerify = $false
if (-not [bool]::TryParse($MihomoSkipCertVerifyText, [ref]$MihomoSkipsCertVerify)) {
    throw 'Selected Mihomo QUIC proxy must set skip-cert-verify to true or false'
}
$Yaml = Set-MihomoProxyEndpoint $Yaml $SelectedProxy '127.0.0.1' $QuicPort
$Yaml = Set-MihomoTopLevelScalar $Yaml 'bind-address' '127.0.0.1'
$Yaml = Set-MihomoTopLevelScalar $Yaml 'allow-lan' 'false'
$InboundConfiguration = Normalize-MihomoIsolatedInbound $Yaml 'quic' $ProxyPort
$Yaml = $InboundConfiguration.Yaml
$ProxyPortKey = $InboundConfiguration.PortKey
$Yaml = Set-MihomoTopLevelScalar $Yaml 'mode' 'rule'
$Yaml = [regex]::Replace(
    $Yaml,
    '(?m)^\s*-\s*IP-CIDR,127\.0\.0\.0/8,DIRECT\s*\r?\n',
    '')
$Yaml = [regex]::Replace(
    $Yaml,
    '(?m)^(\s*-\s*MATCH,)PrismPreview-Active\s*$',
    ('$1' + $ActiveProxy))
Assert-MihomoQuicRoute $Yaml $Protocol $ActiveProxy $ActiveProxy | Out-Null
$Yaml = Set-MihomoIsolatedRouteClosure $Yaml $ActiveProxy
Assert-MihomoRuleMode $Yaml
Assert-MihomoNoDnsListener $Yaml
Assert-MihomoNoShortcutInbounds $Yaml
Assert-MihomoNoProbeGroups $Yaml
Assert-MihomoIsolatedInboundPort $Yaml $ProxyPortKey $ProxyPort
Assert-MihomoCaseNetworkIsolation $Yaml $false
Assert-MihomoIsolatedRouteClosure $Yaml $ActiveProxy $SelectedProxy '127.0.0.1' $QuicPort
Assert-MihomoQuicProxyAlpn $Yaml $SelectedProxy $PrismAlpn
if (Test-MihomoYamlContainsKey $Yaml @(
        'socks-port', 'redir-port', 'tproxy-port', 'port',
        'external-controller', 'external-controller-pipe', 'external-controller-unix',
        'external-controller-tls', 'external-controller-cors', 'secret', 'tun', 'listeners')) {
    throw 'Isolated Mihomo config still contains an unused listener or controller setting'
}
$ChildEnvironment = New-MihomoIsolatedChildEnvironment
# QUIC credentials come from the case-local generated or supplied Prism configuration.  They are never
# copied into the child environment or printed by this script.

    try {
        Write-Utf8NoBom $PrismConfig ($PrismObject | ConvertTo-Json -Depth 100)
        $PrismReadback = Read-MihomoPrismConfigurationReadback $PrismConfig
        Assert-MihomoPrismLocalPaths $PrismReadback.Configuration
        Assert-MihomoPrismCaseLogging $PrismReadback.Configuration $CaseDirectory
        Assert-MihomoPrismDialCarrierBackend $PrismReadback.Configuration 0
        Assert-MihomoPrismConfigurationCase `
            -Configuration $PrismReadback.Configuration `
            -Mode 'quic' -TcpPort $TcpPort -OperationsPort $PrismOperationsPort `
            -ListenerAddress '127.0.0.1' `
            -UdpPort 0 -QuicPort $QuicPort `
            -QuicProtocolId ('protocol-' + $Protocol) `
            -QuicSecretReference $QuicSecretReference `
            -ExpectedQuicCredential $PrismCredential
        $PrismConfigSha256 = $PrismReadback.Sha256
    }
    catch {
        if (Test-Path -LiteralPath $PrismConfig) {
            [void](Remove-MihomoCaseFile $CaseDirectory $PrismConfig)
        }
        throw
    }

    $TargetProcess = Start-Process -FilePath $FileServerExecutable `
        -ArgumentList @($TargetRoot, $TargetPort, '1') `
        -WorkingDirectory $RepositoryRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'target.stdout.log')) `
        -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'target.stderr.log')) `
        -Environment $ChildEnvironment
    $TargetProcessOwner = Register-MihomoOwnedProcess $Started $TargetProcess $FileServerExecutable
    $TargetReady = $false
    for ($Index = 0; $Index -lt 40; $Index++) {
        if ($TargetProcess.HasExited) {
            throw "Target server exited with code $($TargetProcess.ExitCode)"
        }
        if (Test-MihomoOwnedTcpPort $TargetProcessOwner $TargetPort '127.0.0.1') {
            $TargetReady = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $TargetReady) {
        throw 'Target TCP endpoint is not exclusively owned on loopback'
    }

    $PrismProcess = Start-Process -FilePath $PrismExecutable `
        -ArgumentList @($PrismConfig) `
        -WorkingDirectory $RepositoryRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'prism.stdout.log')) `
        -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory 'prism.stderr.log')) `
        -Environment $ChildEnvironment
    $PrismProcessOwner = Register-MihomoOwnedProcess $Started $PrismProcess $PrismExecutable

    $Ready = $false
    for ($Index = 0; $Index -lt 60; $Index++) {
        Start-Sleep -Milliseconds 250
        if ($PrismProcess.HasExited) {
            throw "Prism exited with code $($PrismProcess.ExitCode)"
        }
        $ReadyLog = Join-Path $CaseDirectory 'prism.stdout.log'
        $ReadyText = if (Test-Path $ReadyLog) { Get-Content $ReadyLog -Raw } else { '' }
        if ($ReadyText -match 'quic_socket_ready=true') {
            if ((Test-MihomoOwnedTcpPort $PrismProcessOwner $TcpPort '127.0.0.1') -and
                (Test-MihomoOwnedUdpPort $PrismProcessOwner $QuicPort '127.0.0.1')) {
                Assert-MihomoTcpPortNotOwned $PrismProcessOwner $PrismOperationsPort
                $Ready = $true
                break
            }
        }
    }
    if (-not $Ready) {
        throw 'QUIC readiness timeout'
    }

    for ($Attempt = 1; $Attempt -le $RepeatCount; $Attempt++) {
        $AttemptProxyPort = if ($Attempt -eq 1) {
            $ProxyPort
        } else {
            $ProxyAvoidPorts = @($TcpPort, $QuicPort, $TargetPort, $ProxyPort,
                $PrismOperationsPort)
            foreach ($UsedProxyPort in $UsedProxyPorts) {
                $ProxyAvoidPorts += $UsedProxyPort
            }
            Get-NextLoopbackPort $ProxyAvoidPorts
        }
        if (-not $UsedProxyPorts.Add([int]$AttemptProxyPort)) {
            throw 'Unable to reserve a fresh proxy port for this QUIC attempt'
        }
        $ControllerAvoidPorts = @(
            $TcpPort, $QuicPort, $TargetPort, $ProxyPort, $PrismOperationsPort, $AttemptProxyPort)
        foreach ($UsedProxyPort in $UsedProxyPorts) {
            $ControllerAvoidPorts += $UsedProxyPort
        }
        foreach ($UsedControllerPort in $UsedControllerPorts) {
            $ControllerAvoidPorts += $UsedControllerPort
        }
        $AttemptControllerPort = Get-NextLoopbackPort $ControllerAvoidPorts
        [void]$UsedControllerPorts.Add($AttemptControllerPort)
        $AttemptControllerSecret = New-MihomoControllerSecret
        [void]$SensitiveValues.Add($AttemptControllerSecret)
        $AttemptHome = Join-Path $CaseDirectory ("mihomo-home-{0}" -f $Attempt)
        $AttemptHome = New-MihomoCaseSubdirectory $CaseDirectory (Split-Path -Leaf $AttemptHome)
        [void]$TemporaryDirectories.Add($AttemptHome)
        $AttemptConfig = Join-Path $AttemptHome 'config.yaml'
        $AttemptYaml = Set-MihomoTopLevelScalar $Yaml $ProxyPortKey ([string]$AttemptProxyPort)
        $AttemptYaml = Set-MihomoTopLevelScalar $AttemptYaml 'external-controller' `
            "127.0.0.1:$AttemptControllerPort"
        $AttemptYaml = Set-MihomoTopLevelScalar $AttemptYaml 'secret' $AttemptControllerSecret
        Assert-MihomoNoDnsListener $AttemptYaml
        Assert-MihomoNoShortcutInbounds $AttemptYaml
        Assert-MihomoNoProbeGroups $AttemptYaml
        Assert-MihomoIsolatedInboundPort $AttemptYaml $ProxyPortKey $AttemptProxyPort
        Assert-MihomoCaseNetworkIsolation `
            $AttemptYaml $true $AttemptControllerPort $AttemptControllerSecret
        Assert-MihomoIsolatedRouteClosure `
            $AttemptYaml $ActiveProxy $SelectedProxy '127.0.0.1' $QuicPort
        Assert-MihomoQuicProxyAlpn $AttemptYaml $SelectedProxy $PrismAlpn
        $AttemptExpectedChain = @(Get-MihomoExpectedRouteChain $AttemptYaml $ActiveProxy)
        Write-Utf8NoBom $AttemptConfig $AttemptYaml
        $AttemptConfigReadback = Get-Content -LiteralPath $AttemptConfig -Raw
        Assert-MihomoNoDnsListener $AttemptConfigReadback
        Assert-MihomoNoShortcutInbounds $AttemptConfigReadback
        Assert-MihomoNoProbeGroups $AttemptConfigReadback
        Assert-MihomoIsolatedInboundPort `
            $AttemptConfigReadback $ProxyPortKey $AttemptProxyPort
        Assert-MihomoCaseNetworkIsolation `
            $AttemptConfigReadback $true $AttemptControllerPort $AttemptControllerSecret
        Assert-MihomoIsolatedRouteClosure `
            $AttemptConfigReadback $ActiveProxy $SelectedProxy '127.0.0.1' $QuicPort
        $AttemptAlpn = @(Get-MihomoQuicProxyAlpn $AttemptConfigReadback $SelectedProxy)
        Assert-MihomoQuicProxyAlpn $AttemptConfigReadback $SelectedProxy $PrismAlpn
        $AttemptConfigSha256 = Get-Sha256 $AttemptConfig
        $MihomoOut = Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory ("mihomo-{0}.stdout.log" -f $Attempt))
        $MihomoErr = Get-MihomoCaseArtifactPath $CaseDirectory `
            (Join-Path $CaseDirectory ("mihomo-{0}.stderr.log" -f $Attempt))
        $Mihomo = $null
        $MihomoOwner = $null
        try {
            $MihomoArguments = '-d "{0}" -f "{1}"' -f $AttemptHome, $AttemptConfig
            $Mihomo = Start-Process -FilePath $MihomoExecutable `
                -ArgumentList $MihomoArguments `
                -WorkingDirectory $AttemptHome -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory $MihomoOut) `
                -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory $MihomoErr) `
                -Environment $ChildEnvironment
            $MihomoOwner = Register-MihomoOwnedProcess $Started $Mihomo $MihomoExecutable
            if ($MihomoOwner.Stopped) {
                throw 'Mihomo exited before its isolated configuration could be verified'
            }
            $MihomoIdentity = Get-CimInstance Win32_Process `
                -Filter "ProcessId=$($Mihomo.Id)" -ErrorAction SilentlyContinue
            $CommandLine = if ($null -eq $MihomoIdentity) { '' } else { [string]$MihomoIdentity.CommandLine }
            if ($MihomoOwner.Stopped -or $null -eq $MihomoIdentity -or
                -not (Test-MihomoOwnedProcessIdentity $MihomoOwner) -or
                -not [string]::Equals([string]$MihomoIdentity.ExecutablePath,
                    $MihomoOwner.Path, [System.StringComparison]::OrdinalIgnoreCase) -or
                $CommandLine.IndexOf($AttemptConfig, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
                throw 'Started Mihomo did not receive the exact isolated executable and config'
            }
            $Listening = $false
            for ($Index = 0; $Index -lt 60; $Index++) {
                Start-Sleep -Milliseconds 250
                if ($Mihomo.HasExited) {
                    throw "Mihomo exited with code $($Mihomo.ExitCode)"
                }
                Assert-MihomoNoUnexpectedDefaultProxyListener $MihomoOwner
                if ((Test-MihomoOwnedTcpPort $MihomoOwner $AttemptProxyPort '127.0.0.1') -and
                    (Test-MihomoOwnedUdpPort $MihomoOwner $AttemptProxyPort '127.0.0.1') -and
                    (Test-MihomoOwnedTcpPort $MihomoOwner $AttemptControllerPort '127.0.0.1')) {
                    $Listening = $true
                    break
                }
            }
            if (-not $Listening) {
                throw 'Mihomo QUIC proxy ownership or loopback readiness timeout'
            }
            $ProxySelection = Get-MihomoSelectedProxyChainSnapshot `
                $AttemptControllerPort $AttemptControllerSecret $MihomoOwner `
                $AttemptExpectedChain
            $ProxySelectionSha256 = Get-Sha256Bytes (
                [System.Text.UTF8Encoding]::new($false).GetBytes(
                    ($ProxySelection | ConvertTo-Json -Depth 12 -Compress)))
            if (-not (Test-MihomoOwnedTcpPort $TargetProcessOwner $TargetPort '127.0.0.1') -or
                -not (Test-MihomoOwnedTcpPort $PrismProcessOwner $TcpPort '127.0.0.1') -or
                -not (Test-MihomoOwnedUdpPort $PrismProcessOwner $QuicPort '127.0.0.1') -or
                -not (Test-MihomoOwnedTcpPort $MihomoOwner $AttemptProxyPort '127.0.0.1') -or
                -not (Test-MihomoOwnedUdpPort $MihomoOwner $AttemptProxyPort '127.0.0.1')) {
                throw 'QUIC request endpoints are not exclusively owned loopback sockets'
            }
            Assert-MihomoTcpPortNotOwned $PrismProcessOwner $PrismOperationsPort
            $CurlStdoutPath = Join-Path $CaseDirectory ("curl-{0}.stdout.log" -f $Attempt)
            $CurlStderrPath = Join-Path $CaseDirectory ("curl-{0}.stderr.log" -f $Attempt)
            $CurlResponsePath = Join-Path $TargetRoot ("curl-response-{0}.bin" -f $Attempt)
            $CurlStdoutPath = Get-MihomoCaseArtifactPath $CaseDirectory $CurlStdoutPath
            $CurlStderrPath = Get-MihomoCaseArtifactPath $CaseDirectory $CurlStderrPath
            $CurlResponsePath = Get-MihomoCaseArtifactPath $CaseDirectory $CurlResponsePath
            $CurlArguments = ('-q --noproxy= --proxy=http://127.0.0.1:{0} ' +
                '--limit-rate 256k --max-time 30 ' +
                '--output "{1}" ' +
                '--silent --show-error --write-out "\nHTTP_CODE=%{{http_code}}\n" ' +
                'http://127.0.0.1:{2}/hello.txt') -f $AttemptProxyPort, $CurlResponsePath, $TargetPort
            Assert-MihomoCurlArgumentsDisableDefaults $CurlArguments
            $CurlProcess = Start-Process -FilePath $CurlExecutable -ArgumentList $CurlArguments `
                -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput (Get-MihomoCaseArtifactPath $CaseDirectory $CurlStdoutPath) `
                -RedirectStandardError (Get-MihomoCaseArtifactPath $CaseDirectory $CurlStderrPath)
            $CurlOwner = Register-MihomoOwnedProcess $Started $CurlProcess $CurlExecutable
            $CurlSourceEndpoint = $null
            $RouteProof = $null
            $ControllerApiResponded = $false
            $ControllerSnapshotCount = 0
            $RouteDeadline = [DateTime]::UtcNow.AddSeconds(20)
            while ([DateTime]::UtcNow -lt $RouteDeadline -and $null -eq $RouteProof) {
                $CurlProcess.Refresh()
                if ($CurlProcess.HasExited -or
                    -not (Test-MihomoOwnedProcessIdentity $CurlOwner)) {
                    break
                }
                $CurrentCurlEndpoint = Get-QuicCurlProxyEndpoint $CurlOwner $AttemptProxyPort
                if ($null -eq $CurrentCurlEndpoint) {
                    if ($null -ne $CurlSourceEndpoint) {
                        break
                    }
                    Start-Sleep -Milliseconds 25
                    continue
                }
                if ($null -eq $CurlSourceEndpoint) {
                    $CurlSourceEndpoint = $CurrentCurlEndpoint
                } elseif ($CurlSourceEndpoint.Address -ne $CurrentCurlEndpoint.Address -or
                    $CurlSourceEndpoint.Port -ne $CurrentCurlEndpoint.Port -or
                    $CurlSourceEndpoint.RemoteAddress -ne $CurrentCurlEndpoint.RemoteAddress -or
                    $CurlSourceEndpoint.RemotePort -ne $CurrentCurlEndpoint.RemotePort) {
                    throw 'The owned curl process changed its active proxy source endpoint'
                }
                if ($null -ne $CurlSourceEndpoint) {
                    $RequestEvidence = [pscustomobject]@{
                        SourceAddress = $CurlSourceEndpoint.Address
                        SourcePort = $CurlSourceEndpoint.Port
                        TargetAddress = '127.0.0.1'
                        TargetPort = $TargetPort
                        InboundPort = $AttemptProxyPort
                        Network = 'tcp'
                        ExpectedRoute = $ActiveProxy
                        ExpectedChain = $AttemptExpectedChain
                    }
                    $Snapshot = $null
                    try {
                        $Snapshot = Get-MihomoConnectionsSnapshot `
                            $AttemptControllerPort $AttemptControllerSecret $MihomoOwner
                        $ControllerApiResponded = $true
                        $ControllerSnapshotCount++
                    }
                    catch {
                    }
                    if ($null -ne $Snapshot) {
                        $CurlRows = [System.Collections.Generic.List[object]]::new()
                        foreach ($Connection in @($Snapshot.connections)) {
                            $Evidence = Get-QuicConnectionEvidenceForCurl $Connection $RequestEvidence
                            if ($null -ne $Evidence) {
                                [void]$CurlRows.Add($Evidence)
                            }
                        }
                        if ($CurlRows.Count -gt 1) {
                            throw 'Mihomo reported multiple active rows for the curl source endpoint'
                        }
                        if ($CurlRows.Count -eq 1 -and $null -ne $CurlRows[0].Evidence) {
                            $RouteProof = [pscustomobject]@{
                                ConnectionId = $CurlRows[0].ConnectionId
                                SourceAddress = $CurlRows[0].SourceAddress
                                SourcePort = $CurlRows[0].SourcePort
                                Evidence = $CurlRows[0].Evidence
                                MatchedRouteRows = $CurlRows.Count
                            }
                            break
                        }
                    }
                }
                Start-Sleep -Milliseconds 25
            }
            if ($null -eq $RouteProof) {
                if ($null -eq $CurlSourceEndpoint) {
                    throw 'curl did not expose one loopback TCP endpoint to its proxy while active'
                }
                if (-not $ControllerApiResponded) {
                    throw 'The authenticated Mihomo connections API did not return a valid snapshot'
                }
                throw 'Mihomo did not expose the unique curl connection route before it closed'
            }
            if (-not $CurlProcess.WaitForExit(35000)) {
                throw "curl request did not exit: PID $($CurlProcess.Id)"
            }
            $ExitCode = $CurlProcess.ExitCode
            $CurlOwner.Process.Refresh()
            if (-not $CurlOwner.Process.HasExited) {
                throw 'curl process exit could not be verified after its wait completed'
            }
            $CurlOwner.Stopped = $true
            if (-not (Test-Path -LiteralPath $CurlResponsePath -PathType Leaf)) {
                throw 'curl response body output is missing'
            }
            $CurlResponsePath = Get-MihomoCaseArtifactPath $CaseDirectory $CurlResponsePath
            $ActualResponse = [System.IO.File]::ReadAllBytes($CurlResponsePath)
            Assert-MihomoExactResponseBody $ActualResponse $ExpectedTargetResponse
            $CurlStdout = @()
            if (Test-Path -LiteralPath $CurlStdoutPath) {
                $CurlStdout = @(Get-Content -LiteralPath $CurlStdoutPath)
            }
            $CurlStderr = @()
            if (Test-Path -LiteralPath $CurlStderrPath) {
                $CurlStderr = @(Get-Content -LiteralPath $CurlStderrPath)
            }
            $HttpCodes = [System.Collections.Generic.List[int]]::new()
            foreach ($OutputLine in $CurlStdout) {
                $HttpMatch = [regex]::Match([string]$OutputLine,
                    '^\s*HTTP_CODE=(?<code>\d{3})\s*$')
                if ($HttpMatch.Success) {
                    $HttpCodes.Add([int]$HttpMatch.Groups['code'].Value)
                }
            }
            if ($HttpCodes.Count -ne 1) {
                throw 'curl stdout did not contain exactly one HTTP status marker'
            }
            $HttpCode = $HttpCodes[0]
            $ActualBodySha256 = Get-Sha256Bytes $ActualResponse
            $TargetBodySha256 = Get-Sha256Bytes $ExpectedTargetResponse
            $SingleRequestCorrelation = [ordered]@{
                curlInvocationCount = 1
                curlPid = $CurlProcess.Id
                curlSourceAddress = $CurlSourceEndpoint.Address
                curlSourcePort = $CurlSourceEndpoint.Port
                curlRemoteAddress = $CurlSourceEndpoint.RemoteAddress
                curlRemotePort = $CurlSourceEndpoint.RemotePort
                mihomoConnectionId = $RouteProof.ConnectionId
                matchedRouteRows = $RouteProof.MatchedRouteRows
                destinationAddress = $RouteProof.Evidence.DestinationAddress
                destinationPort = $RouteProof.Evidence.DestinationPort
                inboundPort = $RouteProof.Evidence.InboundPort
                network = $RouteProof.Evidence.Network
                route = $RouteProof.Evidence.ExpectedRoute
                chains = @($RouteProof.Evidence.Chains)
                httpCode = $HttpCode
                responseBodyBytes = $ActualResponse.Length
                responseBodySha256 = $ActualBodySha256
                targetBodyBytes = $ExpectedTargetResponse.Length
                targetBodySha256 = $TargetBodySha256
            }
            $Output = @($CurlStdout + $CurlStderr)
            $Output = @($Output | ForEach-Object {
                Protect-MihomoText ([string]$_) @($SensitiveValues)
            })
            Write-Utf8NoBom (Join-Path $CaseDirectory ("curl-{0}.log" -f $Attempt)) `
                ($Output -join "`n")
            $ServerLogDiagnostics = Read-QuicLogDiagnostics -LogRoot $PrismLogRoot
            $Results.Add([ordered]@{
                    attempt = $Attempt
                    prismPid = $PrismProcess.Id
                    mihomoPid = $Mihomo.Id
                    targetPid = $TargetProcess.Id
                    curlPid = $CurlProcess.Id
                    tcpPort = $TcpPort
                    proxyPort = $AttemptProxyPort
                    prismOperationsPort = $PrismOperationsPort
                    quicPort = $QuicPort
                    targetPort = $TargetPort
                    exitCode = $ExitCode
                    httpCode = $HttpCode
                    responseBodyMatched = $true
                    responseBodyBytes = $ExpectedTargetResponse.Length
                    targetBodyBytes = $ExpectedTargetResponse.Length
                    bodySha256 = $ActualBodySha256
                    targetBodySha256 = $TargetBodySha256
                    controllerPort = $AttemptControllerPort
                    controllerListenerOwnerPid = $Mihomo.Id
                    controllerListenerOwned = $true
                    endpointOwnershipVerified = $true
                    controllerProxiesApiResponded = $true
                    controllerSelectedChain = @($AttemptExpectedChain)
                    controllerProxiesSha256 = $ProxySelectionSha256
                    controllerRouteApiResponded = $ControllerApiResponded
                    controllerRouteSnapshotCount = $ControllerSnapshotCount
                    routeEvidenceObserved = $true
                    routeBodyCorrelationUnderSingleCurl = $SingleRequestCorrelation
                    prismRelayLogCorrelation = 'not_available'
                    prismRelaySessionIdWireObserved = $false
                    routeEvidence = [ordered]@{
                        connectionId = $RouteProof.ConnectionId
                        sourceAddress = $RouteProof.SourceAddress
                        sourcePort = $RouteProof.SourcePort
                        destinationAddress = $RouteProof.Evidence.DestinationAddress
                        destinationPort = $RouteProof.Evidence.DestinationPort
                        inboundPort = $RouteProof.Evidence.InboundPort
                        network = $RouteProof.Evidence.Network
                        rule = $RouteProof.Evidence.Rule
                        rulePayload = $RouteProof.Evidence.RulePayload
                        expectedRoute = $RouteProof.Evidence.ExpectedRoute
                        expectedChain = @($AttemptExpectedChain)
                        chains = @($RouteProof.Evidence.Chains)
                    }
                    curlSourceAddress = $CurlSourceEndpoint.Address
                    curlSourcePort = $CurlSourceEndpoint.Port
                    curlRemoteAddress = $CurlSourceEndpoint.RemoteAddress
                    curlRemotePort = $CurlSourceEndpoint.RemotePort
                    output = ($Output -join "`n")
                    expectedProtocol = $Protocol
                    generatedPrismProfile = [bool]$GeneratedPrismProfile
                    dnsSourceHandling = 'source template is read-only; dns section is removed from the case copy'
                    certificateValidation = [ordered]@{
                        mihomoSkipCertVerify = [bool]$MihomoSkipsCertVerify
                        mihomoPeerValidation = if ($MihomoSkipsCertVerify) {
                            'disabled'
                        } else { 'enabled-by-config' }
                        runnerTrustValidation = 'not-independently-validated'
                    }
                    serverName = [ordered]@{
                        configuredValuesMatched = $true
                        wireObserved = $false
                    }
                    alpn = [ordered]@{
                        configuredValuesMatched = $true
                        values = @($AttemptAlpn)
                        wireObserved = $false
                    }
                    serverLogDiagnosticAvailable = [bool]$ServerLogDiagnostics.Available
                    serverLogPath = $ServerLogDiagnostics.Path
                    serverLogExcerpt = Protect-MihomoText $ServerLogDiagnostics.Excerpt @($SensitiveValues)
                    prismExecutable = $PrismExecutable
                    prismSha256 = $PrismSha256
                    prismConfig = $PrismConfig
                    prismConfigSha256 = $PrismConfigSha256
                    mihomoExecutable = $MihomoExecutable
                    mihomoSha256 = $MihomoSha256
                    mihomoTemplatePath = $MihomoTemplatePath
                    mihomoTemplateSha256 = $MihomoTemplateSha256
                    targetExecutable = $FileServerExecutable
                    curlExecutable = $CurlExecutable
                    configPath = $AttemptConfig
                    configSha256 = $AttemptConfigSha256
                    targetRoot = $TargetRoot
                    ownedProcessIdentities = @(
                        Get-MihomoOwnedProcessEvidence 'prism' $PrismProcessOwner
                        Get-MihomoOwnedProcessEvidence 'mihomo' $MihomoOwner
                        Get-MihomoOwnedProcessEvidence 'target' $TargetProcessOwner
                        Get-MihomoOwnedProcessEvidence 'curl' $CurlOwner
                    )
                    cleanup = [ordered]@{
                        mihomoExited = $false
                        curlExited = $true
                        homeRemoved = $false
                        configRemoved = $false
                        processesExited = $false
                        cleanupFailures = @()
                        cleanupSucceeded = $false
                        prismConfigRemoved = $false
                        prismExited = $false
                        targetExited = $false
                        targetRootRemoved = $false
                        generatedCertificateRemoved = $false
                        generatedPrivateKeyRemoved = $false
                        ownedProcessIdentityVerified = $true
                    }
                })
        }
        finally {
            $Exited = Invoke-MihomoCleanupAction $CleanupFailures 'Mihomo process stop' {
                Stop-MihomoOwnedProcess $MihomoOwner
            }
            $ConfigRemoved = if ($Exited) {
                Invoke-MihomoCleanupAction $CleanupFailures 'Mihomo config removal' {
                    Remove-MihomoCaseFile $CaseDirectory $AttemptConfig
                }
            }
            else {
                $false
            }
            $HomeRemoved = if ($Exited) {
                Invoke-MihomoCleanupAction $CleanupFailures 'Mihomo home removal' {
                    Remove-MihomoCaseDirectory $CaseDirectory $AttemptHome
                }
            }
            else {
                $false
            }
            $Result = $Results | Select-Object -Last 1
            if ($null -ne $Result) {
                $Result.cleanup.mihomoExited = [bool]$Exited
                $Result.cleanup.homeRemoved = [bool]$HomeRemoved
                $Result.cleanup.configRemoved = [bool]$ConfigRemoved
            }
            $AttemptControllerSecret = ''
        }
    }
}
finally {
    $AttemptControllerSecret = ''
    $AllProcessesExited = $true
    foreach ($OwnedProcess in $Started) {
        if (-not (Invoke-MihomoCleanupAction $CleanupFailures 'owned process stop' {
                    Stop-MihomoOwnedProcess $OwnedProcess
                })) {
            $AllProcessesExited = $false
        }
    }
    $PrismExited = $null -eq $PrismProcessOwner -or $PrismProcessOwner.Stopped
    $TargetExited = $null -eq $TargetProcessOwner -or $TargetProcessOwner.Stopped
    $TargetRootRemoved = if ($AllProcessesExited) {
        Invoke-MihomoCleanupAction $CleanupFailures 'target fixture removal' {
            Remove-MihomoCaseDirectory $CaseDirectory $TargetRoot
        }
    }
    else {
        $false
    }
    if ($AllProcessesExited) {
        [void](Invoke-MihomoCleanupAction $CleanupFailures 'case log redaction' {
            Protect-MihomoCaseLogs $CaseDirectory @($SensitiveValues)
        })
        [void](Invoke-MihomoCleanupAction $CleanupFailures 'Prism config removal' {
            Remove-MihomoCaseFile $CaseDirectory $PrismConfig
        })
        if ($GeneratedPrismProfile) {
            [void](Invoke-MihomoCleanupAction $CleanupFailures 'generated certificate removal' {
                Remove-MihomoCaseFile $CaseDirectory $GeneratedCertificatePath
            })
            [void](Invoke-MihomoCleanupAction $CleanupFailures 'generated private key removal' {
                Remove-MihomoCaseFile $CaseDirectory $GeneratedPrivateKeyPath
            })
        }
        foreach ($TemporaryDirectory in $TemporaryDirectories) {
            [void](Invoke-MihomoCleanupAction $CleanupFailures 'temporary Mihomo home removal' {
                Remove-MihomoCaseDirectory $CaseDirectory $TemporaryDirectory
            })
        }
        if ($Results.Count -eq 0) {
            [void](Invoke-MihomoCleanupAction $CleanupFailures 'empty Prism log directory removal' {
                if (-not (Test-Path -LiteralPath $PrismLogRoot)) {
                    return $true
                }
                if (@(Get-ChildItem -LiteralPath $PrismLogRoot -Force -ErrorAction Stop).Count -gt 0) {
                    return $true
                }
                return (Remove-MihomoCaseDirectory $CaseDirectory $PrismLogRoot)
            })
        }
    }
    $PrismConfigRemoved = -not (Test-Path -LiteralPath $PrismConfig)
    $GeneratedCertificateRemoved = -not (Test-Path -LiteralPath $GeneratedCertificatePath)
    $GeneratedPrivateKeyRemoved = -not (Test-Path -LiteralPath $GeneratedPrivateKeyPath)
    foreach ($Result in $Results) {
        $Result.cleanup.prismConfigRemoved = [bool]$PrismConfigRemoved
        $Result.cleanup.generatedCertificateRemoved = [bool]$GeneratedCertificateRemoved
        $Result.cleanup.generatedPrivateKeyRemoved = [bool]$GeneratedPrivateKeyRemoved
        $Result.cleanup.prismExited = [bool]$PrismExited
        $Result.cleanup.targetExited = [bool]$TargetExited
        $Result.cleanup.targetRootRemoved = [bool]$TargetRootRemoved
        $Result.cleanup.processesExited = [bool]$AllProcessesExited
        $Result.cleanup.cleanupFailures = @($CleanupFailures.ToArray())
        $Result.cleanup.cleanupSucceeded = $CleanupFailures.Count -eq 0 -and $AllProcessesExited
        if (-not $AllProcessesExited -or $CleanupFailures.Count -gt 0) {
            $Result.exitCode = 1
            $CleanupMessage = if (-not $AllProcessesExited) {
                'cleanup could not verify every owned process; case configs and active logs were retained'
            } else {
                'cleanup item failed; see sanitized cleanupFailures'
            }
            $Result.output = (($Result.output,
                $CleanupMessage) -join "`n")
        }
    }
    if ($CleanupFailures.Count -gt 0 -and $Results.Count -eq 0) {
        try {
            Write-Utf8NoBom (Join-Path $CaseDirectory 'cleanup-failures.log') `
                ($CleanupFailures -join "`n")
        }
        catch {
        }
    }
    foreach ($Result in $Results) {
        $Result.cleanup.configRemoved = -not (Test-Path -LiteralPath $Result.configPath)
        $Result.cleanup.homeRemoved = -not (Test-Path -LiteralPath (Split-Path -Parent $Result.configPath))
    }
}

if ($RepeatCount -lt 1 -or $Results.Count -ne $RepeatCount) {
    throw 'Mihomo QUIC runner did not complete every requested attempt'
}
    for ($Index = 0; $Index -lt $Results.Count; $Index++) {
        $SelectedChain = @($Results[$Index].controllerSelectedChain | ForEach-Object { [string]$_ })
        $ExpectedChain = @(
            $(if ($Protocol -eq 'hysteria2') { 'prism-hysteria2' } else { 'prism-tuic' }),
            $(if ($Protocol -eq 'hysteria2') { 'Hysteria2 QUIC' } else { 'TUIC v5 QUIC' }))
        if (-not [bool]$Results[$Index].controllerProxiesApiResponded -or
            $SelectedChain.Count -ne $ExpectedChain.Count) {
            throw 'Mihomo QUIC attempt does not report a verified controller proxy chain'
        }
        for ($ChainIndex = 0; $ChainIndex -lt $ExpectedChain.Count; $ChainIndex++) {
            if (-not [string]::Equals($SelectedChain[$ChainIndex], $ExpectedChain[$ChainIndex],
                    [System.StringComparison]::OrdinalIgnoreCase)) {
                throw 'Mihomo QUIC attempt controller proxy chain differs from its case'
            }
        }
    }
Protect-MihomoObjectInPlace $Results @($SensitiveValues)
$Json = $Results | ConvertTo-Json -Depth 12
Write-Utf8NoBom (Join-Path $CaseDirectory 'results.json') $Json
$Json
if (@($Results | Where-Object {
            $_.exitCode -ne 0 -or $_.output -notmatch 'HTTP_CODE=200' -or
            -not $_.responseBodyMatched -or -not $_.routeEvidenceObserved -or
            -not $_.cleanup.cleanupSucceeded
        }).Count -gt 0) {
    exit 1
}
$PersistedResults = @(Get-Content -LiteralPath (Join-Path $CaseDirectory 'results.json') -Raw |
    ConvertFrom-Json)
Assert-MihomoQuicRunnerContract $CaseDirectory $PersistedResults
