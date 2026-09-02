# check-common-headers.ps1 - G7 gate: Preview header ownership completeness
# Usage: pwsh scripts/check_common_headers.ps1 [-RepoRoot <path>] [-CheckMirror]
# Checks preview/Foundation, preview/Transport, and the remaining tests/common
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
    (Join-Path $RepoRoot "preview/Foundation")
    (Join-Path $RepoRoot "preview/Transport")
    (Join-Path $RepoRoot "preview/Net")
    (Join-Path $RepoRoot "preview/Runtime")
    (Join-Path $RepoRoot "preview/Composition")
    (Join-Path $RepoRoot "preview/Protocols")
)
$testSupportDir = Join-Path $RepoRoot "tests/TestSupport"
$commonDir = Join-Path $RepoRoot "tests/common"
$previewCmake = Join-Path $RepoRoot "preview/CMakeLists.txt"
$testSupportCmake = Join-Path $testSupportDir "CMakeLists.txt"
$commonCmake = Join-Path $commonDir "CMakeLists.txt"

$requiredPaths = $previewRoots + @(
    $testSupportDir
    $commonDir
    $previewCmake
    $testSupportCmake
    $commonCmake
)
foreach ($requiredPath in $requiredPaths) {
    if (-not (Test-Path $requiredPath)) {
        Write-Error "Required path not found: $requiredPath"
        exit 1
    }
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
$registrations += Get-TargetSources $previewCmake "preview"
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

# 3. Mirror-drift check. Fault Code/Compatible, Exception, and Memory are
#    strict mirrors after the documented namespace/path normalization. Fault
#    Handling intentionally diverges because Preview protocol errors are
#    converted at the Preview/Composition boundary, not in production psm.
$mirrorFailures = @()
if ($CheckMirror) {
    function Normalize-MirrorContent {
        param([string]$Content)

        # Documentation and line layout are not behavior. The only semantic
        # normalization permitted here is the established namespace/path and
        # Preview PascalCase -> psm snake_case conversion.
        $Content = [regex]::Replace($Content, '(?s)/\*.*?\*/', '')
        $Content = [regex]::Replace($Content, '//[^\r\n]*', '')
        $Content = $Content.Replace('preview/Foundation/', 'prism/foundation/')
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
        @{ src = "preview/Foundation/Fault/Code.hpp"; dst = "include/prism/foundation/fault/code.hpp" },
        @{ src = "preview/Foundation/Fault/Compatible.hpp"; dst = "include/prism/foundation/fault/compatible.hpp" },
        @{ src = "preview/Foundation/Exception/Deviant.hpp"; dst = "include/prism/foundation/exception/deviant.hpp" },
        @{ src = "preview/Foundation/Exception/Network.hpp"; dst = "include/prism/foundation/exception/network.hpp" },
        @{ src = "preview/Foundation/Exception/Protocol.hpp"; dst = "include/prism/foundation/exception/protocol.hpp" },
        @{ src = "preview/Foundation/Exception/Security.hpp"; dst = "include/prism/foundation/exception/security.hpp" },
        @{ src = "preview/Foundation/Memory/Container.hpp"; dst = "include/prism/foundation/memory/container.hpp" },
        @{ src = "preview/Foundation/Memory/Pool.hpp"; dst = "include/prism/foundation/memory/pool.hpp" }
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
    if ($mirrorFailures.Count -gt 0) {
        Write-Host "Mirror gate FAILED ($($mirrorFailures.Count) drift(s)):" -ForegroundColor Red
        $mirrorFailures | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        Write-Host "Only documented namespace/path normalization is allowed."
        exit 1
    } else {
        Write-Host "Mirror check passed"
    }
}

Write-Host "G7 gate passed: $($diskFiles.Count) headers, $($registrations.Count) owned entries"
exit 0
