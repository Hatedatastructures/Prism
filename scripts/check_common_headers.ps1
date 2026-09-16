# check-common-headers.ps1 - G7 gate: Preview header ownership completeness
# Usage: pwsh scripts/check_common_headers.ps1 [-RepoRoot <path>] [-CheckMirror]
# Checks Preview module roots and the remaining tests/common
# headers against their owning target_sources blocks.
# Exit code: 0 = pass, 1 = gate failure

param(
    [string]$RepoRoot = "",
    [switch]$CheckMirror
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

$previewRoots = @(
    (Join-Path $RepoRoot "Preview/Account")
    (Join-Path $RepoRoot "Preview/Application")
    (Join-Path $RepoRoot "Preview/Composition")
    (Join-Path $RepoRoot "Preview/Foundation")
    (Join-Path $RepoRoot "Preview/Ingress")
    (Join-Path $RepoRoot "Preview/Lifecycle")
    (Join-Path $RepoRoot "Preview/Net")
    (Join-Path $RepoRoot "Preview/Operations")
    (Join-Path $RepoRoot "Preview/Protocols")
    (Join-Path $RepoRoot "Preview/Resource")
    (Join-Path $RepoRoot "Preview/Runtime")
    (Join-Path $RepoRoot "Preview/Scheduler")
    (Join-Path $RepoRoot "Preview/Statistics")
    (Join-Path $RepoRoot "Preview/Transport")
)
$testSupportDir = Join-Path $RepoRoot "tests/TestSupport"
$commonDir = Join-Path $RepoRoot "tests/common"
$previewCmake = Join-Path $RepoRoot "Preview/CMakeLists.txt"
$testSupportCmake = Join-Path $testSupportDir "CMakeLists.txt"
$commonCmake = Join-Path $commonDir "CMakeLists.txt"

$requiredPaths = $previewRoots + @(
    $testSupportDir
    $commonDir
    $previewCmake
    $testSupportCmake
    $commonCmake
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
        if ($line -match '^target_sources\(\s*([A-Za-z][A-Za-z0-9_]*)\s+INTERFACE\s*$') {
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
        if ($line -match '^[A-Za-z0-9_/.-]+\.hpp$') {
            $registrations += [pscustomobject]@{
                Target = $activeTarget
                Path = "$PathPrefix/$line"
            }
        }
    }
    return $registrations
}

# 1. Collect all public headers in the active preview and tests/common roots.
$diskFiles = @()
$sourceRoots = $previewRoots + @($testSupportDir, $commonDir)
foreach ($sourceRoot in $sourceRoots) {
    $diskFiles += Get-ChildItem -Path $sourceRoot -Recurse -Filter *.hpp -File |
        ForEach-Object {
            $_.FullName.Substring($RepoRoot.Length + 1).Replace("\", "/")
        }
}
$diskFiles = $diskFiles | Sort-Object -Unique

# 2. Parse target_sources from both CMake owners.
$registrations = @()
    $registrations += Get-TargetSources $previewCmake "Preview"
$registrations += Get-TargetSources $testSupportCmake "tests/TestSupport"
$registrations += Get-TargetSources $commonCmake "tests/common"
$cmakeEntries = $registrations | ForEach-Object { $_.Path }
$allowedTargetPattern = '^(Preview|TestSupport|ProductionTestSupport)[A-Za-z0-9]*$'
$problems = @()

$unknownTargets = $registrations | Where-Object { $_.Target -notmatch $allowedTargetPattern }
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

# 3. Preview is a standalone project. Its PascalCase headers are no longer
#    required to mirror the production psm headers; -CheckMirror is retained
#    as an explicit no-op for callers that still pass the legacy switch.
$mirrorFailures = @()
if ($false) {
    function Normalize-MirrorContent {
        param([string]$Content)

        # Documentation and line layout are not behavior. The only semantic
        # normalization permitted here is the established namespace/path and
        # Preview PascalCase -> psm snake_case conversion.
        $Content = [regex]::Replace($Content, '(?s)/\*.*?\*/', '')
        $Content = [regex]::Replace($Content, '//[^\r\n]*', '')
        $Content = $Content.Replace('Preview/Foundation/', 'prism/foundation/')
        $Content = $Content.Replace('Preview::', 'psm::')
        $Content = $Content.Replace('std::hash', 'hash')
        $Content = $Content.Replace('boost::system::error_category', 'error_category')
        $Content = $Content.Replace('} namespace psm::fault {', '')
        $Content = [regex]::Replace(
            $Content,
            '(?<![A-Za-z0-9_])[A-Z][A-Za-z0-9]*(?:_)?(?![A-Za-z0-9_])',
            {
                param($Match)
                $Token = $Match.Value
                $Suffix = ''
                if ($Token.EndsWith('_')) {
                    $Token = $Token.Substring(0, $Token.Length - 1)
                    $Suffix = '_'
                }
                $Token = [regex]::Replace($Token, '([A-Z]+)([A-Z][a-z])', '$1_$2')
                $Token = [regex]::Replace($Token, '([a-z0-9])([A-Z])', '$1_$2')
                return $Token.ToLowerInvariant() + $Suffix
            })
        $Content = [regex]::Replace($Content, '\s+', ' ').Trim()
        $Content = $Content.Replace('} namespace psm::fault {', '')
        $Content = $Content.Replace('namespace psm { }', '')
        $Content = [regex]::Replace($Content, '\s+', ' ').Trim()
        return $Content
    }

    # The strict mirror is an explicit eight-file contract. CowMap, Pointer,
    # and Fault/Handling are intentionally not mirror candidates.
    $mirrorFiles = @(
        @{ src = "Preview/Foundation/Fault/Code.hpp"; dst = "include/prism/foundation/fault/code.hpp" },
        @{ src = "Preview/Foundation/Fault/Compatible.hpp"; dst = "include/prism/foundation/fault/compatible.hpp" },
        @{ src = "Preview/Foundation/Exception/Deviant.hpp"; dst = "include/prism/foundation/exception/deviant.hpp" },
        @{ src = "Preview/Foundation/Exception/Network.hpp"; dst = "include/prism/foundation/exception/network.hpp" },
        @{ src = "Preview/Foundation/Exception/Protocol.hpp"; dst = "include/prism/foundation/exception/protocol.hpp" },
        @{ src = "Preview/Foundation/Exception/Security.hpp"; dst = "include/prism/foundation/exception/security.hpp" },
        @{ src = "Preview/Foundation/Memory/Container.hpp"; dst = "include/prism/foundation/memory/container.hpp" },
        @{ src = "Preview/Foundation/Memory/Pool.hpp"; dst = "include/prism/foundation/memory/pool.hpp" }
    )
    foreach ($pair in $mirrorFiles) {
        $srcFile = Join-Path $RepoRoot $pair.src
        $dstFile = Join-Path $RepoRoot $pair.dst
        if (-not (Test-Path $srcFile) -or -not (Test-Path $dstFile)) {
            $mirrorFailures += "  MIRROR-MISSING $($pair.src) <-> $($pair.dst)"
            continue
        }
        $srcContent = Normalize-MirrorContent ([IO.File]::ReadAllText($srcFile))
        $dstContent = Normalize-MirrorContent ([IO.File]::ReadAllText($dstFile))
        if ($srcContent -cne $dstContent) {
            $mirrorFailures += "  MIRROR-DIFF $($pair.src) <-> $($pair.dst)"
        }
    }
}

if ($problems.Count -gt 0) {
    Write-Host "G7 gate FAILED:" -ForegroundColor Red
    $problems | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "Fix: assign each public header to exactly one module target_sources block"
    exit 1
}

if ($CheckMirror) {
    Write-Host "Mirror check skipped: Preview is standalone and has no production mirror contract"
}

Write-Host "G7 gate passed: $($diskFiles.Count) headers, $($registrations.Count) owned entries"
exit 0
