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
    if ($Output -match '(?im)(echo mismatch|wire mismatch|header mismatch|implementation mismatch)') {
        return 'implementation-mismatch'
    }
    if ($ExitCode -ne 0) {
        return 'protocol-failure'
    }
    return 'pass'
}

function New-InteropResult {
    param(
        [Parameter(Mandatory = $true)][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$Direction,
        [Parameter(Mandatory = $true)][string]$Scenario,
        [Parameter(Mandatory = $true)][string]$Implementation,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$Platform,
        [Parameter(Mandatory = $true)][ValidateSet('pass', 'protocol-failure', 'implementation-mismatch', 'environment-unavailable', 'blocked-production-prerequisite')][string]$Status,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Artifacts = @(),
        [string]$Timestamp = ([DateTime]::UtcNow.ToString('o'))
    )

    return [ordered]@{
        protocol = $Protocol
        direction = $Direction
        scenario = $Scenario
        implementation = $Implementation
        commit = $Commit
        platform = $Platform
        status = $Status
        exit_code = $ExitCode
        command = $Command
        artifacts = @($Artifacts)
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
        [switch]$BlockedProductionPrerequisite
    )

    $CaseName = ($Protocol + '_' + $Direction + '_' + $Scenario) -replace '[^A-Za-z0-9_.-]', '_'
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $StdoutPath = Join-Path $OutputDirectory ($CaseName + '.stdout.log')
    $StderrPath = Join-Path $OutputDirectory ($CaseName + '.stderr.log')
    $ResultPath = Join-Path $OutputDirectory ($CaseName + '.json')
    $Command = $Executable + ' ' + ($Arguments -join ' ')
    $ExitCode = 127
    $Output = ''

    if (Test-Path -LiteralPath $Executable -PathType Leaf) {
        $Process = Start-Process -FilePath $Executable -ArgumentList $Arguments -PassThru -Wait -WindowStyle Hidden `
            -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
        $ExitCode = $Process.ExitCode
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
        -ExitCode $ExitCode -Command $Command -Artifacts @($StdoutPath, $StderrPath)
    Write-InteropResult -Result $Result -Path $ResultPath
    return $Result
}

if (-not $LibraryOnly) {
    throw 'Invoke-Interop.ps1 is a library; use Invoke-InteropCase from a runner script.'
}
