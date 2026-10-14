function Get-OperationsCommandHeaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port
    )

    $Uri = "http://127.0.0.1:$Port/Operations/Bootstrap"
    $Bootstrap = Invoke-RestMethod -Method Get -Uri $Uri -TimeoutSec 5
    $Token = [string]$Bootstrap.command_token
    $Incarnation = [string]$Bootstrap.process_incarnation
    $Capabilities = @($Bootstrap.capabilities)
    if ([string]$Bootstrap.api_version -ne '1' -or
        [string]::IsNullOrWhiteSpace([string]$Bootstrap.process_id) -or
        $Incarnation -notmatch '^[0-9a-fA-F]{32}$' -or
        $Token -notmatch '^[0-9a-fA-F]{64}$' -or
        $Capabilities -notcontains 'process.drain') {
        throw 'Operations bootstrap contract is unavailable'
    }

    return @{ Authorization = "Bearer $Token" }
}
