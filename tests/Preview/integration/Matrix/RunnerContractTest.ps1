[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CaseDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ResolvedCase = (Resolve-Path -LiteralPath $CaseDirectory).Path
$ResultsPath = Join-Path $ResolvedCase 'results.json'
if (-not (Test-Path -LiteralPath $ResultsPath)) {
    throw "Matrix runner did not produce results.json: $ResultsPath"
}

$Results = @(Get-Content -LiteralPath $ResultsPath -Raw | ConvertFrom-Json)
if ($Results.Count -eq 0) {
    throw 'Matrix runner produced no attempts.'
}

$RequiredFields = @(
    'previewExecutable',
    'previewSha256',
    'previewConfigSha256',
    'mihomoExecutable',
    'mihomoSha256',
    'expectedProtocol',
    'serverLogObserved',
    'serverLogPath',
    'serverLogExcerpt',
    'cleanup'
)
foreach ($Result in $Results) {
    foreach ($Field in $RequiredFields) {
        if (-not ($Result.PSObject.Properties.Name -contains $Field)) {
            throw "Attempt $($Result.attempt) is missing result field '$Field'."
        }
    }
    if ($Result.previewSha256 -notmatch '^[0-9A-F]{64}$' -or
        $Result.previewConfigSha256 -notmatch '^[0-9A-F]{64}$' -or
        $Result.mihomoSha256 -notmatch '^[0-9A-F]{64}$') {
        throw "Attempt $($Result.attempt) has an invalid SHA-256 record."
    }
    if ([string]::IsNullOrWhiteSpace($Result.expectedProtocol) -or
        -not [bool]$Result.serverLogObserved -or
        -not (Test-Path -LiteralPath $Result.serverLogPath) -or
        $Result.serverLogExcerpt -notmatch ('\[Protocol=' + [regex]::Escape($Result.expectedProtocol) + '\]') -or
        $Result.serverLogExcerpt -notmatch 'stage=relay outcome=success|stage=mux outcome=success') {
        throw "Attempt $($Result.attempt) has no correlated successful $($Result.expectedProtocol) data-plane log."
    }
    foreach ($CleanupField in @('mihomoExited', 'homeRemoved', 'configRemoved', 'previewConfigRemoved')) {
        if (-not ($Result.cleanup.PSObject.Properties.Name -contains $CleanupField) -or
            -not [bool]$Result.cleanup.$CleanupField) {
            throw "Attempt $($Result.attempt) cleanup field '$CleanupField' is not true."
        }
    }
    if (Test-Path -LiteralPath $Result.previewConfig) {
        throw "Attempt $($Result.attempt) left temporary Preview config: $($Result.previewConfig)"
    }
}

$ResidualHomes = @(Get-ChildItem -LiteralPath $ResolvedCase -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'mihomo-home*' })
if ($ResidualHomes.Count -ne 0) {
    throw "Matrix runner left temporary Mihomo homes: $($ResidualHomes.Name -join ', ')"
}

Write-Host "MATRIX RUNNER CONTRACT PASSED ($($Results.Count) attempt(s))"
