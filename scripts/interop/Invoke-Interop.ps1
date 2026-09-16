param(
    [switch]$LibraryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-InteropStatus {
    param(
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [AllowEmptyString()][string]$Output,
        [switch]$BlockedProductionPrerequisite
    )

    if ($BlockedProductionPrerequisite) {
        return 'blocked-production-prerequisite'
    }
    if ($ExitCode -eq 127 -or $Output -match '(?im)(command not found|no such file|cannot find the path|not recognized)') {
        return 'environment-unavailable'
    }
    if ($Output -match '(?im)^\s*BLOCKED:\s*interface-gap\b') {
        return 'interface-gap'
    }
    if ($Output -match '(?im)(echo mismatch|wire mismatch|header mismatch|implementation mismatch)') {
        return 'implementation-mismatch'
    }
    if ($ExitCode -ne 0) {
        return 'protocol-failure'
    }
    return 'pass'
}

function Get-InteropMatrixScope {
    param(
        [AllowEmptyString()][string]$PrismExe
    )

    if ([string]::IsNullOrWhiteSpace($PrismExe)) {
        return 'preview-only'
    }
    return 'full'
}

function Get-GateDClassification {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('full', 'preview-only')][string]$Scope,
        [Parameter(Mandatory = $true)][ValidateSet('pass', 'failed', 'blocked-production-prerequisite', 'environment-unavailable', 'interface-gap')][string]$Status
    )

    if ($Status -eq 'blocked-production-prerequisite') {
        if ($Scope -eq 'full') {
            return 'production-blocked'
        }
        return 'preview-only-blocked'
    }
    if ($Status -in @('environment-unavailable', 'interface-gap')) {
        return 'preview-only-blocked'
    }
    if ($Status -eq 'failed') {
        return 'failed'
    }
    return 'pass'
}

function Get-InteropReferenceVersions {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot
    )

    $Versions = [ordered]@{}
    $GoMod = Join-Path $RepoRoot 'tests/go/go.mod'
    if (-not (Test-Path -LiteralPath $GoMod -PathType Leaf)) {
        return $Versions
    }
    foreach ($Line in (Get-Content -LiteralPath $GoMod -ErrorAction Stop)) {
        if ($Line -match '^\s*([^\s]+)\s+(v[^\s]+)(?:\s+//.*)?$') {
            $Versions[$Matches[1]] = $Matches[2]
        }
    }
    return $Versions
}

function New-InteropResult {
    param(
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$Direction,
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][string]$Implementation,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$Platform,
        [Parameter(Mandatory = $true)][ValidateSet('pass', 'protocol-failure', 'implementation-mismatch', 'environment-unavailable', 'interface-gap', 'blocked-production-prerequisite')][string]$Status,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Artifacts = @(),
        [ValidateSet('Deterministic', 'MixedTrial', 'direct-handler', 'not-exercised')][string]$RecognitionMode = 'not-exercised',
        [string]$CandidateProfile = '',
        [string]$Route = '',
        [double]$WallTimeMs = 0,
        [UInt64]$PeakWorkingSetBytes = 0,
        [string]$Timestamp = ([DateTime]::UtcNow.ToString('o'))
    )

    return [ordered]@{
        protocol = $Protocol
        direction = $Direction
        scenario = $Scenario
        implementation = $Implementation
        recognition_mode = $RecognitionMode
        candidate_profile = $CandidateProfile
        route = $Route
        commit = $Commit
        platform = $Platform
        status = $Status
        exit_code = $ExitCode
        command = $Command
        artifacts = @($Artifacts)
        wall_time_ms = $WallTimeMs
        peak_working_set_bytes = $PeakWorkingSetBytes
        metrics_available = ($WallTimeMs -gt 0 -or $PeakWorkingSetBytes -gt 0)
        timestamp_utc = $Timestamp
    }
}

function Write-InteropResult {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $Parent = Split-Path -Parent $Path
    if ($Parent) {
        New-Item -ItemType Directory -Path $Parent -Force | Out-Null
    }
    $Result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Clear-InteropArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Get-ChildItem -LiteralPath $OutputDirectory -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @('.json', '.log') } |
        Remove-Item -Force -ErrorAction Stop
}

function Invoke-InteropCase {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$Direction,
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][string]$Implementation,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$Platform,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [switch]$BlockedProductionPrerequisite,
        [ValidateSet('Deterministic', 'MixedTrial', 'direct-handler', 'not-exercised')][string]$RecognitionMode = 'not-exercised',
        [string]$CandidateProfile = '',
        [string]$Route = ''
    )

    $CaseName = ($Protocol + '_' + $Direction + '_' + $Scenario) -replace '[^A-Za-z0-9_.-]', '_'
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $StdoutPath = Join-Path $OutputDirectory ($CaseName + '.stdout.log')
    $StderrPath = Join-Path $OutputDirectory ($CaseName + '.stderr.log')
    $ResultPath = Join-Path $OutputDirectory ($CaseName + '.json')
    $Command = $Executable + ' ' + ($Arguments -join ' ')
    $ExitCode = 127
    $Output = ''
    $WallTimeMs = 0.0
    [UInt64]$PeakWorkingSetBytes = 0

    if (Test-Path -LiteralPath $Executable -PathType Leaf) {
        $Process = $null
        $Watch = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $Process = Start-Process -FilePath $Executable -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
            while (-not $Process.HasExited) {
                try {
                    $Process.Refresh()
                    $WorkingSet = [UInt64]$Process.PeakWorkingSet64
                    if ($WorkingSet -gt $PeakWorkingSetBytes) {
                        $PeakWorkingSetBytes = $WorkingSet
                    }
                } catch {
                    # Process can exit between Refresh and PeakWorkingSet64.
                }
                Start-Sleep -Milliseconds 25
            }
            $Process.Refresh()
            $ExitCode = $Process.ExitCode
            try {
                $WorkingSet = [UInt64]$Process.PeakWorkingSet64
                if ($WorkingSet -gt $PeakWorkingSetBytes) {
                    $PeakWorkingSetBytes = $WorkingSet
                }
            } catch {
            }
        } finally {
            $Watch.Stop()
            $WallTimeMs = $Watch.Elapsed.TotalMilliseconds
            if ($Process -and -not $Process.HasExited) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        Start-Sleep -Milliseconds 20
        $Output = ((Get-Content -LiteralPath $StdoutPath -Raw -ErrorAction SilentlyContinue),
                   (Get-Content -LiteralPath $StderrPath -Raw -ErrorAction SilentlyContinue) -join "`n")
    } else {
        "environment unavailable: executable not found: $Executable" | Set-Content -LiteralPath $StdoutPath -Encoding UTF8
        '' | Set-Content -LiteralPath $StderrPath -Encoding UTF8
        $Output = Get-Content -LiteralPath $StdoutPath -Raw
    }

    $Status = Get-InteropStatus -ExitCode $ExitCode -Output $Output -BlockedProductionPrerequisite:$BlockedProductionPrerequisite
    $Result = New-InteropResult -Protocol $Protocol -Direction $Direction -Scenario $Scenario `
        -Implementation $Implementation -Commit $Commit -Platform $Platform -Status $Status `
        -ExitCode $ExitCode -Command $Command -Artifacts @($StdoutPath, $StderrPath) `
        -RecognitionMode $RecognitionMode -CandidateProfile $CandidateProfile -Route $Route `
        -WallTimeMs $WallTimeMs -PeakWorkingSetBytes $PeakWorkingSetBytes
    Write-InteropResult -Result $Result -Path $ResultPath
    return $Result
}

if (-not $LibraryOnly) {
    throw 'Invoke-Interop.ps1 is a library; use Invoke-InteropCase from a runner script.'
}
