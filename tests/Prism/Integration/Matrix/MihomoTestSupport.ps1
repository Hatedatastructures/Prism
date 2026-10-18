Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-MihomoExecutable {
    param([Parameter(Mandatory = $true)][string]$Executable)

    if (Test-Path -LiteralPath $Executable -PathType Leaf) {
        return (Resolve-Path -LiteralPath $Executable).Path
    }
    return (Get-Command -Name $Executable -CommandType Application -ErrorAction Stop).Source
}
