# check-common-headers.ps1 - G7 gate: tests/common header registration completeness
# Usage: pwsh scripts/check_common_headers.ps1 [-RepoRoot <path>] [-CheckMirror]
# Checks: every .hpp on disk is registered in tests/common/CMakeLists.txt target_sources,
#         no duplicate/stale entries; optional mirror-drift warnings (whitelist extensible).
# Exit code: 0 = pass, 1 = gate failure

param(
    [string]$RepoRoot = "",
    [switch]$CheckMirror
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

$commonDir = Join-Path $RepoRoot "tests/common"
$cmakeFile = Join-Path $commonDir "CMakeLists.txt"
if (-not (Test-Path $cmakeFile)) {
    Write-Error "CMakeLists not found: $cmakeFile"
    exit 1
}

# 1. Collect .hpp files on disk (relative to tests/common, forward slashes)
$diskFiles = Get-ChildItem -Path $commonDir -Recurse -Filter *.hpp -File |
    ForEach-Object { $_.FullName.Substring($commonDir.Length + 1).Replace("\", "/") } |
    Sort-Object -Unique

# 2. Parse target_sources entries from CMakeLists
$cmakeEntries = Get-Content $cmakeFile -Encoding UTF8 |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -match "^[^#].*\.hpp$" } |
    ForEach-Object { ($_ -replace "^.*?([A-Za-z0-9_/]+\.hpp)$", '$1').Trim() }

$problems = @()

# 大小写敏感比较：Windows 文件系统不区分大小写，纯大小写改名本地可见但
# Linux CI（case-sensitive）会在 CMake 阶段失败——门禁必须与 CI 同口径
$missing = $diskFiles | Where-Object { $cmakeEntries -cnotcontains $_ }
if ($missing) {
    $problems += "MISSING (on disk but not registered):"
    $problems += $missing | ForEach-Object { "  $_" }
}

$stale = $cmakeEntries | Sort-Object -Unique | Where-Object { $diskFiles -cnotcontains $_ }
if ($stale) {
    $problems += "STALE (registered but missing on disk):"
    $problems += $stale | ForEach-Object { "  $_" }
}

$dups = $cmakeEntries | Group-Object -CaseSensitive | Where-Object Count -gt 1
if ($dups) {
    $problems += "DUPLICATE (registered more than once):"
    $problems += $dups | ForEach-Object { "  $($_.Count)x $($_.Name)" }
}

# 3. Mirror-drift check (whitelist extension point; SPEC.md 镜像清单 must register forks)
$mirrorWarnings = @()
if ($CheckMirror) {
    # Whitelist: files intentionally forked from production (documented in SPEC.md)
    $mirrorWhitelist = @(
        # core/crypto/* forked as a whole: preview needs self-contained
        # implementation (aead wraps BoringSSL EVP_AEAD, hkdf adds TLS 1.3
        # Expand-Label, blake3 adds derive_key mode, etc.); no sync constraint.
        "Core/Crypto/Aead.hpp",
        "Core/Crypto/Base64.hpp",
        "Core/Crypto/Blake3.hpp",
        "Core/Crypto/Block.hpp",
        "Core/Crypto/Crypto.hpp",
        "Core/Crypto/Hkdf.hpp",
        "Core/Crypto/Sha224.hpp",
        "Core/Crypto/X25519.hpp"
    )
    # PascalCase（2026-08-22 规范 v2）：旧小写路径在 Linux case-sensitive
    # 文件系统上 Test-Path 失败 → 镜像检查被静默跳过
    $mirrorPairs = @(
        @{ src = "Core/Fault";       dst = "include/prism/foundation/fault" },
        @{ src = "Core/Exception";   dst = "include/prism/foundation/exception" },
        @{ src = "Core/Memory";      dst = "include/prism/foundation/memory" },
        @{ src = "Core/Crypto";      dst = "include/prism/crypto" }
    )
    foreach ($pair in $mirrorPairs) {
        $srcDir = Join-Path $commonDir $pair.src
        $dstDir = Join-Path $RepoRoot $pair.dst
        if (-not (Test-Path $srcDir) -or -not (Test-Path $dstDir)) { continue }
        Get-ChildItem -Path $srcDir -Filter *.hpp -File | ForEach-Object {
            $dstFile = Join-Path $dstDir $_.Name
            if (-not (Test-Path $dstFile)) { return }
            $rel = "$($pair.src)/$($_.Name)"
            if ($mirrorWhitelist -contains $rel) { return }
            $diff = Compare-Object (Get-Content $_.FullName -Encoding UTF8) (Get-Content $dstFile -Encoding UTF8)
            if ($diff) {
                $mirrorWarnings += "  MIRROR-DIFF $rel <-> $($pair.dst)/$($_.Name) ($($diff.Count) line diff)"
            }
        }
    }
}

if ($problems.Count -gt 0) {
    Write-Host "G7 gate FAILED:" -ForegroundColor Red
    $problems | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "Fix: sync tests/common/CMakeLists.txt target_sources after adding/removing headers"
    exit 1
}

if ($CheckMirror) {
    if ($mirrorWarnings.Count -gt 0) {
        Write-Host "Mirror drift warnings ($($mirrorWarnings.Count)):" -ForegroundColor Yellow
        $mirrorWarnings | ForEach-Object { Write-Host $_ }
        Write-Host "Note: whitelisted files are exempt; forks must be registered in SPEC.md 镜像清单"
    } else {
        Write-Host "Mirror check passed"
    }
}

Write-Host "G7 gate passed: $($diskFiles.Count) headers, $((($cmakeEntries | Sort-Object -Unique)).Count) registered entries"
exit 0
