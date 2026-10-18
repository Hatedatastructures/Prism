[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ProxyPort,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$TargetPort,
    [Parameter(Mandatory = $true)][string]$PayloadText
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-ExactBytes {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][int]$Count
    )

    $Buffer = [byte[]]::new($Count)
    $Offset = 0
    while ($Offset -lt $Count) {
        $BytesRead = $Stream.Read($Buffer, $Offset, $Count - $Offset)
        if ($BytesRead -eq 0) {
            throw 'SOCKS5 control connection closed before the full reply arrived.'
        }
        $Offset += $BytesRead
    }
    return ,$Buffer
}

function Read-SocksAddress {
    param([Parameter(Mandatory = $true)][System.IO.Stream]$Stream)

    $AddressType = (Read-ExactBytes $Stream 1)[0]
    switch ($AddressType) {
        1 { $AddressBytes = Read-ExactBytes $Stream 4; $Address = [System.Net.IPAddress]::new($AddressBytes) }
        3 {
            $Length = (Read-ExactBytes $Stream 1)[0]
            $NameBytes = Read-ExactBytes $Stream $Length
            $Address = [System.Net.Dns]::GetHostAddresses([Text.Encoding]::ASCII.GetString($NameBytes))[0]
        }
        4 { $AddressBytes = Read-ExactBytes $Stream 16; $Address = [System.Net.IPAddress]::new($AddressBytes) }
        default { throw "Unsupported SOCKS5 address type: $AddressType" }
    }
    $PortBytes = Read-ExactBytes $Stream 2
    $Port = ([int]$PortBytes[0] -shl 8) -bor [int]$PortBytes[1]
    return [System.Net.IPEndPoint]::new($Address, $Port)
}

$Control = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
$Datagram = $null
try {
    $Control.Connect([System.Net.IPAddress]::Loopback, $ProxyPort)
    $Stream = $Control.GetStream()
    $Stream.Write([byte[]](5, 1, 0), 0, 3)
    $GreetingReply = Read-ExactBytes $Stream 2
    if ($GreetingReply[0] -ne 5 -or $GreetingReply[1] -ne 0) {
        throw "Mihomo SOCKS5 did not select no-authentication: $($GreetingReply -join ',')"
    }

    $AssociateRequest = [byte[]](5, 3, 0, 1, 0, 0, 0, 0, 0, 0)
    $Stream.Write($AssociateRequest, 0, $AssociateRequest.Length)
    $ReplyHead = Read-ExactBytes $Stream 3
    if ($ReplyHead[0] -ne 5 -or $ReplyHead[1] -ne 0) {
        throw "Mihomo SOCKS5 UDP ASSOCIATE failed with status $($ReplyHead[1])."
    }
    $Relay = Read-SocksAddress $Stream
    if ($Relay.Port -eq 0) {
        throw 'Mihomo returned an empty UDP relay port.'
    }
    if ([System.Net.IPAddress]::Any.Equals($Relay.Address)) {
        $Relay = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Relay.Port)
    }
    elseif ([System.Net.IPAddress]::IPv6Any.Equals($Relay.Address)) {
        $Relay = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::IPv6Loopback, $Relay.Port)
    }

    $Datagram = [System.Net.Sockets.UdpClient]::new($Relay.AddressFamily)
    $Datagram.Client.ReceiveTimeout = 5000
    $Payload = [Text.Encoding]::UTF8.GetBytes($PayloadText)
    $Request = [byte[]]::new(10 + $Payload.Length)
    $Request[0] = 0
    $Request[1] = 0
    $Request[2] = 0
    $Request[3] = 1
    [System.Net.IPAddress]::Loopback.GetAddressBytes().CopyTo($Request, 4)
    $Request[8] = [byte](($TargetPort -shr 8) -band 0xff)
    $Request[9] = [byte]($TargetPort -band 0xff)
    $Payload.CopyTo($Request, 10)
    [void]$Datagram.Send($Request, $Request.Length, $Relay)

    $Source = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $Response = $Datagram.Receive([ref]$Source)
    if ($Response.Length -lt 10 -or $Response[0] -ne 0 -or $Response[1] -ne 0 -or $Response[2] -ne 0) {
        throw 'Mihomo returned a malformed SOCKS5 UDP packet.'
    }
    $AddressLength = switch ($Response[3]) {
        1 { 4 }
        3 { [int]$Response[4] + 1 }
        4 { 16 }
        default { throw "Unsupported SOCKS5 UDP response address type: $($Response[3])" }
    }
    $PayloadOffset = 4 + $AddressLength + 2
    if ($Response.Length -lt $PayloadOffset) {
        throw 'Mihomo returned a truncated SOCKS5 UDP packet.'
    }
    $ActualPayload = $Response[$PayloadOffset..($Response.Length - 1)]
    $PayloadMatches = $ActualPayload.Length -eq $Payload.Length
    for ($Index = 0; $PayloadMatches -and $Index -lt $Payload.Length; $Index++) {
        $PayloadMatches = $ActualPayload[$Index] -eq $Payload[$Index]
    }
    if (-not $PayloadMatches) {
        throw "UDP echo payload mismatch: expected $($Payload.Length) bytes, got $($ActualPayload.Length)."
    }

    Write-Output ("PASS: mihomo SOCKS5 UDP bytes={0} relay={1} target=127.0.0.1:{2}" -f `
        $ActualPayload.Length, $Relay, $TargetPort)
}
finally {
    if ($null -ne $Datagram) { $Datagram.Dispose() }
    if ($null -ne $Control) { $Control.Dispose() }
}
