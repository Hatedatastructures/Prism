# check-common-headers.ps1 - Prism Include/Src HPP ownership gate.
# Usage: pwsh scripts/check_common_headers.ps1 [-RepoRoot <path>]

param([string]$RepoRoot = "")

$ErrorActionPreference = "Stop"
if (-not $RepoRoot) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

$IncludeRoot = Join-Path $RepoRoot "Include/Prism"
$SourceRoot = Join-Path $RepoRoot "Src/Prism"
$TestSupportDir = Join-Path $RepoRoot "Test/TestSupport"
$ExperimentDir = Join-Path $RepoRoot "Test/Experiments/Prism"
$ProductionCmakeRoot = Join-Path $RepoRoot "Src/Prism"
$TestSupportCmake = Join-Path $TestSupportDir "CMakeLists.txt"
$RequiredPaths = @($IncludeRoot, $SourceRoot, $TestSupportDir, $ProductionCmakeRoot, $TestSupportCmake)

function Assert-ExactPathCase {
    param([string]$Path)
    $FullPath = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $FullPath)) { throw "Required path not found: $FullPath" }
    $Current = [IO.Path]::GetPathRoot($FullPath)
    $Relative = $FullPath.Substring($Current.Length) -replace '^[\\/]+', ''
    foreach ($Component in ($Relative -split '[\\/]')) {
        if ([string]::IsNullOrEmpty($Component)) { continue }
        $Entry = Get-ChildItem -LiteralPath $Current -Force |
            Where-Object { $_.Name -ceq $Component } | Select-Object -First 1
        if (-not $Entry) { throw "Path case mismatch: requested '$FullPath', missing exact entry '$Component' in '$Current'" }
        $Current = Join-Path $Current $Component
    }
}

foreach ($RequiredPath in $RequiredPaths) { Assert-ExactPathCase $RequiredPath }

function Convert-ToRepoRelativePath {
    param([string]$Token, [string]$BaseDirectory)
    $Value = $Token.Trim('"', "'")
    $Value = $Value.Replace('${PROJECT_SOURCE_DIR}/', "$RepoRoot/")
    $Value = $Value.Replace('${CMAKE_SOURCE_DIR}/', "$RepoRoot/")
    $Value = $Value.Replace('${CMAKE_CURRENT_SOURCE_DIR}/', "$BaseDirectory/")
    if (-not [IO.Path]::IsPathRooted($Value)) { $Value = Join-Path $BaseDirectory $Value }
    return [IO.Path]::GetRelativePath($RepoRoot, [IO.Path]::GetFullPath($Value)).Replace('\', '/')
}

function Get-ProductionHeaderRegistrations {
    param([string]$CmakeFile)
    $Text = [IO.File]::ReadAllText($CmakeFile)
    $Directory = Split-Path -Parent $CmakeFile
    $Variables = @{}
    foreach ($SetMatch in [regex]::Matches($Text, '(?is)\bset\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(.*?)\)')) {
        $Name = $SetMatch.Groups[1].Value
        $Values = @()
        foreach ($ValueMatch in [regex]::Matches($SetMatch.Groups[2].Value, '"[^"]*"|\S+')) {
            $Value = $ValueMatch.Value.Trim('"', "'")
            if ($Value -match '\.hpp$') { $Values += $Value }
        }
        if ($Values.Count -gt 0) { $Variables[$Name] = $Values }
    }

    $Registrations = @()
    foreach ($TargetMatch in [regex]::Matches($Text, '(?is)PrismAdd(?:Interface|Static)Target\s*\((.*?)\)')) {
        $Tokens = @([regex]::Matches($TargetMatch.Groups[1].Value, '"[^"]*"|\S+') |
            ForEach-Object { $_.Value.Trim('"', "'") })
        if ($Tokens.Count -lt 1) { continue }
        $Target = $Tokens[0]
        $Section = ""
        foreach ($Token in $Tokens | Select-Object -Skip 1) {
            if ($Token -in @('HEADERS', 'PRIVATE_HEADERS', 'SOURCES')) {
                $Section = $Token
                continue
            }
            if ($Section -notin @('HEADERS', 'PRIVATE_HEADERS')) { continue }
            if ($Token -match '^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$') {
                foreach ($Expanded in $Variables[$Matches[1]]) {
                    if ($Expanded -match '\.hpp$') {
                        $Registrations += [pscustomobject]@{
                            Target = $Target
                            Path = Convert-ToRepoRelativePath $Expanded $Directory
                        }
                    }
                }
                continue
            }
            if ($Token -match '\.hpp$') {
                $Registrations += [pscustomobject]@{
                    Target = $Target
                    Path = Convert-ToRepoRelativePath $Token $Directory
                }
            }
        }
    }
    return $Registrations
}

function Get-LegacyTargetSources {
    param([string]$CmakeFile, [string]$PathPrefix)
    $Registrations = @()
    $Directory = Split-Path -Parent $CmakeFile
    $Text = [IO.File]::ReadAllText($CmakeFile, [Text.Encoding]::UTF8) -replace '(?m)^[ \t]*#.*$', ''
    foreach ($TargetSources in [regex]::Matches($Text, '(?is)\btarget_sources\s*\(\s*([A-Za-z][A-Za-z0-9_]*)\s+(?:INTERFACE|PUBLIC|PRIVATE)\s+(.*?)\)')) {
        $Target = $TargetSources.Groups[1].Value
        foreach ($TokenMatch in [regex]::Matches($TargetSources.Groups[2].Value, '"[^"]*"|\S+')) {
            $Token = $TokenMatch.Value.Trim('"', "'")
            if ($Token -notmatch '\.hpp$') { continue }
            $Path = Convert-ToRepoRelativePath $Token $Directory
            $Registrations += [pscustomobject]@{ Target = $Target; Path = $Path }
        }
    }
    return $Registrations
}

$DiskFiles = @()
foreach ($Root in @($IncludeRoot, $SourceRoot, $TestSupportDir, $ExperimentDir)) {
    if (Test-Path -LiteralPath $Root -PathType Container) {
        $DiskFiles += Get-ChildItem -LiteralPath $Root -Recurse -Filter '*.hpp' -File |
            ForEach-Object { [IO.Path]::GetRelativePath($RepoRoot, $_.FullName).Replace('\', '/') }
    }
}
$DiskFiles = $DiskFiles | Sort-Object -Unique

$Registrations = @()
Get-ChildItem -LiteralPath $ProductionCmakeRoot -Recurse -Filter CMakeLists.txt -File |
    ForEach-Object { $Registrations += Get-ProductionHeaderRegistrations $_.FullName }
$Registrations += Get-LegacyTargetSources $TestSupportCmake 'Test/TestSupport'
if (Test-Path -LiteralPath $ExperimentDir -PathType Container) {
    Get-ChildItem -LiteralPath $ExperimentDir -Recurse -Filter CMakeLists.txt -File | ForEach-Object {
        $Directory = Split-Path -Parent $_.FullName
        $Prefix = [IO.Path]::GetRelativePath($RepoRoot, $Directory).Replace('\', '/')
        $Registrations += Get-LegacyTargetSources $_.FullName $Prefix
    }
}
$CmakeEntries = $Registrations | ForEach-Object { $_.Path }
$AllowedTargetPattern = '^(Prism[A-Za-z0-9]*|TestSupport|Experimental[A-Za-z0-9]*)$'
$Problems = @()

$UnknownTargets = $Registrations | Where-Object { $_.Target -notmatch $AllowedTargetPattern }
if ($UnknownTargets) {
    $Problems += 'UNKNOWN TARGET (header registered on a non-module target):'
    $Problems += $UnknownTargets | ForEach-Object { "  $($_.Target): $($_.Path)" }
}
$OwnerGroups = $Registrations | Group-Object -Property Path
$OwnedExactlyOnce = $OwnerGroups | Where-Object Count -eq 1 | ForEach-Object { $_.Name }
$Missing = $DiskFiles | Where-Object { $OwnedExactlyOnce -cnotcontains $_ }
if ($Missing) {
    $Problems += 'MISSING OR NOT UNIQUELY OWNED (on disk but not registered exactly once):'
    $Problems += $Missing | ForEach-Object { "  $_" }
}
$Stale = $CmakeEntries | Sort-Object -Unique | Where-Object { $DiskFiles -cnotcontains $_ }
if ($Stale) {
    $Problems += 'STALE (registered but missing on disk):'
    $Problems += $Stale | ForEach-Object { "  $_" }
}
$Duplicates = $Registrations | Group-Object -Property Path | Where-Object Count -gt 1
if ($Duplicates) {
    $Problems += 'DUPLICATE (registered more than once):'
    $Problems += $Duplicates | ForEach-Object {
        $Owners = ($_.Group | ForEach-Object { $_.Target }) -join ', '
        "  $($_.Count)x $($_.Name) [$Owners]"
    }
}

if ($Problems.Count -gt 0) {
    $Problems | ForEach-Object { Write-Output $_ }
    Write-Output "Prism Include/Src ownership gate FAILED: $($Problems.Count) issue(s)"
    exit 1
}
Write-Output "Prism Include/Src ownership gate passed: $($DiskFiles.Count) headers, each registered exactly once; public headers, private headers, TestSupport, and experiment headers checked"
exit 0
