# check-common-headers.ps1 - G7 gate: Prism header ownership completeness
# Usage: pwsh scripts/check_common_headers.ps1 [-RepoRoot <path>]
# Checks Prism module roots and the current tests/Prism support tree.
# headers against their owning target_sources blocks.
# Exit code: 0 = pass, 1 = gate failure

param(
    [string]$RepoRoot = ""
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

$prismRoots = @(
    (Join-Path $RepoRoot "Prism/Account")
    (Join-Path $RepoRoot "Prism/Application")
    (Join-Path $RepoRoot "Prism/Boundary")
    (Join-Path $RepoRoot "Prism/Composition")
    (Join-Path $RepoRoot "Prism/Contract")
    (Join-Path $RepoRoot "Prism/Foundation")
    (Join-Path $RepoRoot "Prism/Lifecycle")
    (Join-Path $RepoRoot "Prism/Net")
    (Join-Path $RepoRoot "Prism/Operations")
    (Join-Path $RepoRoot "Prism/Protocols")
    (Join-Path $RepoRoot "Prism/Resource")
    (Join-Path $RepoRoot "Prism/Runtime")
    (Join-Path $RepoRoot "Prism/Statistics")
    (Join-Path $RepoRoot "Prism/Transport")
)
$testSupportDir = Join-Path $RepoRoot "tests/TestSupport"
$experimentDir = Join-Path $RepoRoot "tests/Experiments/Prism"
$prismCmake = Join-Path $RepoRoot "Prism/CMakeLists.txt"
$testSupportCmake = Join-Path $testSupportDir "CMakeLists.txt"

$requiredPaths = $prismRoots + @(
    $testSupportDir
    $prismCmake
    $testSupportCmake
)

function Assert-ExactPathCase {
    param([string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath)) {
        throw "Required path not found: $fullPath"
    }

    $current = [IO.Path]::GetPathRoot($fullPath)
    $relative = ($fullPath.Substring($current.Length) -replace '^[\\/]+', '')
    foreach ($component in ($relative -split '[\\/]')) {
        if ([string]::IsNullOrEmpty($component)) {
            continue
        }
        $entry = Get-ChildItem -LiteralPath $current -Force |
            Where-Object { $_.Name -ceq $component } |
            Select-Object -First 1
        if (-not $entry) {
            throw "Path case mismatch: requested '$fullPath' but '$current' has no exact entry '$component'"
        }
        $current = Join-Path $current $component
    }
}

foreach ($requiredPath in $requiredPaths) {
    Assert-ExactPathCase $requiredPath
}

function Get-TargetSources {
    param(
        [string]$CmakeFile,
        [string]$PathPrefix
    )

    $registrations = @()
    $activeTarget = ""
    $insideTargetSources = $false
    foreach ($rawLine in Get-Content $CmakeFile -Encoding UTF8) {
        $line = $rawLine.Trim()
        if ($line -match '^(?:target_sources|add_library|add_executable)\(\s*([A-Za-z][A-Za-z0-9_]*)(?:\s+(?:(?:INTERFACE|PUBLIC|PRIVATE|STATIC|SHARED|MODULE|OBJECT)\s*))?$') {
            $activeTarget = $Matches[1]
            $insideTargetSources = $true
            continue
        }
        if (-not $insideTargetSources) { continue }
        if ($line -eq ')') {
            $activeTarget = ""
            $insideTargetSources = $false
            continue
        }
        $sourceLine = $line.TrimEnd(')').Trim('"')
        if ($sourceLine -match '^\$\{(?:CMAKE_SOURCE_DIR|PROJECT_SOURCE_DIR)\}/(tests/Experiments/Prism/[A-Za-z0-9_/.-]+\.hpp)$') {
            $registrations += [pscustomobject]@{
                Target = $activeTarget
                Path = $Matches[1]
            }
            continue
        }
        if ($line -match '^([A-Za-z0-9_/.-]+\.hpp)\)?$') {
            $registrations += [pscustomobject]@{
                Target = $activeTarget
                Path = "$PathPrefix/$($Matches[1])"
            }
        }
    }
    return $registrations
}

# 1. Collect public headers in the active Prism and test support roots.
$diskFiles = @()
$sourceRoots = $prismRoots + @($testSupportDir, $experimentDir)
foreach ($sourceRoot in $sourceRoots) {
    $diskFiles += Get-ChildItem -Path $sourceRoot -Recurse -Filter *.hpp -File |
        ForEach-Object {
            $_.FullName.Substring($RepoRoot.Length + 1).Replace("\", "/")
        }
}
$diskFiles = $diskFiles | Sort-Object -Unique

# 2. Parse target_sources from both CMake owners.
$registrations = @()
$prismCmakeFiles = Get-ChildItem -LiteralPath (Join-Path $RepoRoot "Prism") -Recurse -Filter CMakeLists.txt -File
foreach ($CmakeFile in $prismCmakeFiles) {
    $Directory = Split-Path -Parent $CmakeFile.FullName
    $PathPrefix = $Directory.Substring($RepoRoot.Length + 1).Replace("\", "/")
    $registrations += Get-TargetSources $CmakeFile.FullName $PathPrefix
}
$registrations += Get-TargetSources $testSupportCmake "tests/TestSupport"
Get-ChildItem -LiteralPath (Join-Path $RepoRoot "tests/Prism") -Recurse -Filter CMakeLists.txt -File |
    ForEach-Object {
        $Directory = Split-Path -Parent $_.FullName
        $PathPrefix = $Directory.Substring($RepoRoot.Length + 1).Replace("\", "/")
        $registrations += Get-TargetSources $_.FullName $PathPrefix |
            Where-Object { $_.Path.StartsWith('tests/Experiments/Prism/') }
    }
$cmakeEntries = $registrations | ForEach-Object { $_.Path }
$allowedTargetPattern = '^(Prism[A-Za-z0-9]*|TestSupport|Experimental[A-Za-z0-9]*)$'
$problems = @()

$unknownTargets = $registrations | Where-Object {
    $_.Target -notmatch $allowedTargetPattern -and
    !$_.Path.StartsWith('tests/Experiments/Prism/')
}
if ($unknownTargets) {
    $problems += "UNKNOWN TARGET (header registered on a non-module target):"
    $problems += $unknownTargets | ForEach-Object { "  $($_.Target): $($_.Path)" }
}

$ownerGroups = $registrations | Group-Object -Property Path
$ownedExactlyOnce = $ownerGroups |
    Where-Object Count -eq 1 |
    ForEach-Object { $_.Name }
$missing = $diskFiles | Where-Object { $ownedExactlyOnce -cnotcontains $_ }
if ($missing) {
    $problems += "MISSING OR NOT UNIQUELY OWNED (on disk but not registered exactly once):"
    $problems += $missing | ForEach-Object { "  $_" }
}

$stale = $cmakeEntries | Sort-Object -Unique |
    Where-Object { $diskFiles -cnotcontains $_ }
if ($stale) {
    $problems += "STALE (registered but missing on disk):"
    $problems += $stale | ForEach-Object { "  $_" }
}

$duplicates = $registrations | Group-Object -Property Path |
    Where-Object Count -gt 1
if ($duplicates) {
    $problems += "DUPLICATE (registered more than once):"
    $problems += $duplicates | ForEach-Object {
        $owners = ($_.Group | ForEach-Object { $_.Target }) -join ', '
        "  $($_.Count)x $($_.Name) [$owners]"
    }
}

if ($problems.Count -gt 0) {
    Write-Host "G7 gate FAILED:" -ForegroundColor Red
    $problems | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "Fix: assign each public header to exactly one module target_sources block"
    exit 1
}

Write-Host "G7 gate passed: $($diskFiles.Count) headers, $($registrations.Count) owned entries"
exit 0
