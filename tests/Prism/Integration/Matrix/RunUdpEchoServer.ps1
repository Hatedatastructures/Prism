[CmdletBinding()]
param([Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Server = [System.Net.Sockets.UdpClient]::new(
    [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Port))
try {
    while ($true) {
        $Remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $Payload = $Server.Receive([ref]$Remote)
        [void]$Server.Send($Payload, $Payload.Length, $Remote)
    }
}
finally {
    $Server.Dispose()
}
