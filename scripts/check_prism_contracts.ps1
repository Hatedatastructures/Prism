# Prism 正式源码结构与模块方向门禁；不构建、不改写仓库。
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$PrismRoot = Join-Path $RepoRoot 'Prism'
$Problems = [Collections.Generic.List[string]]::new()
$Headers = @(Get-ChildItem -LiteralPath $PrismRoot -Recurse -File -Filter '*.hpp')
$FilePaths = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
Get-ChildItem -LiteralPath $PrismRoot -Recurse -File | ForEach-Object {
    $RelativePath = [IO.Path]::GetRelativePath($RepoRoot, $_.FullName).Replace('\', '/')
    $FilePaths.Add($RelativePath, $RelativePath)
}
$Consumers = [Collections.Generic.List[IO.FileInfo]]::new()
foreach ($Header in $Headers) { $Consumers.Add($Header) }
foreach ($TestRoot in @('tests/Prism', 'tests/Experiments/Prism')) {
    $TestPath = Join-Path $RepoRoot $TestRoot
    if (Test-Path -LiteralPath $TestPath -PathType Container) {
        Get-ChildItem -LiteralPath $TestPath -Recurse -File |
            Where-Object { $_.Extension -in '.hpp', '.h', '.cpp', '.cc', '.cxx' } |
            ForEach-Object { $Consumers.Add($_) }
    }
}
$Implementations = @(Get-ChildItem -LiteralPath $PrismRoot -Recurse -File |
    Where-Object { $_.Extension -in '.cpp', '.cc', '.cxx' })
foreach ($Implementation in $Implementations) {
    $Problems.Add("生产实现扩展名未退役: $($Implementation.FullName)")
}

$RetiredIncludes = @(
    'Prism/Runtime/Contract/DataPlane.hpp',
    'Prism/Runtime/Contract/Handler.hpp',
    'Prism/Composition/Adapters/TypedResult.hpp',
    'Prism/Composition/Adapters/DataPlane.hpp',
    'Prism/Composition/Adapters/ProtocolAdapter.hpp',
    'Prism/Composition/Adapters/DatagramService.hpp',
    'Prism/Composition/Adapters/Socks5Factory.hpp',
    'Prism/Composition/UdpService.hpp',
    'Prism/Composition/UdpServiceLogging.hpp',
    'Prism/Composition/Settings/Json.hpp',
    'Prism/Composition/Settings/Loader.hpp',
    'Prism/Runtime/Front/UdpFront.hpp',
    'Prism/Runtime/Front/QuicFront.hpp',
    'Prism/Foundation/Utility/Account/Directory.hpp',
    'Prism/Foundation/Utility/Account/Authenticator.hpp',
    'Prism/Foundation/Utility/Coroutine/Registry.hpp'
)

foreach ($RetiredPath in $RetiredIncludes) {
    if ($FilePaths.ContainsKey($RetiredPath)) {
        $Problems.Add("已要求退役的生产源码仍存在: $RetiredPath")
    }
}
foreach ($RelativePath in $FilePaths.Values) {
    if ($RelativePath -match '^Prism/(Ingress|Runtime/Front|Composition/Api|Scheduler|Net/Route|Net/Outbound)/' -and
        [IO.Path]::GetExtension($RelativePath) -in '.hpp', '.h', '.cpp', '.cc', '.cxx') {
        $Problems.Add("已要求退役的生产目录仍公开源码: $RelativePath")
    }
}

foreach ($Header in $Consumers) {
    $Relative = [IO.Path]::GetRelativePath($RepoRoot, $Header.FullName).Replace('\', '/')
    $Lines = [IO.File]::ReadAllLines($Header.FullName)
    if ($Relative.StartsWith('Prism/') -and $Lines.Length -gt 600) {
        $Problems.Add("$Relative`: $($Lines.Length) 行超过 600")
    }
    for ($Index = 0; $Index -lt $Lines.Length; ++$Index) {
        if ($Lines[$Index] -notmatch '^\s*#\s*include\s*[<"](Prism/[^>"]+)[>"]') {
            continue
        }
        $Include = $Matches[1]
        $Position = "$Relative`:$($Index + 1)"
        $ResolvedTestInclude = $null
        if ($Relative.StartsWith('tests/')) {
            $TestIncludePath = Join-Path $RepoRoot ("tests/" + $Include)
            if (Test-Path -LiteralPath $TestIncludePath -PathType Leaf) {
                $ResolvedTestInclude = [IO.Path]::GetRelativePath($RepoRoot, $TestIncludePath).Replace('\', '/')
            }
        }
        if ($ResolvedTestInclude) {
            $ResolvedTestRelative = $ResolvedTestInclude.Substring('tests/'.Length)
            if ($ResolvedTestRelative -cne $Include) {
                $Problems.Add("$Position include大小写与测试文件路径不一致: $Include -> $ResolvedTestRelative")
            }
        }
        elseif (!$FilePaths.ContainsKey($Include)) {
            $Problems.Add("$Position 引用不存在的生产文件 $Include")
        }
        elseif ($FilePaths[$Include] -cne $Include) {
            $Problems.Add("$Position include大小写与真实路径不一致: $Include -> $($FilePaths[$Include])")
        }
        if ($RetiredIncludes -contains $Include -or
            $Include -match '^Prism/(Ingress|Runtime/Front|Composition/Api|Scheduler|Net/Route|Net/Outbound)/') {
            $Problems.Add("$Position 仍引用已要求退役的接口 $Include")
        }
        if ($Relative -match '^Prism/Protocols/' -and
            $Include -match '^Prism/(Composition|Application|Runtime)/') {
            $Problems.Add("$Position 协议反向依赖 $Include")
        }
        if ($Relative -match '^Prism/Contract/' -and
            $Include -match '^Prism/(Composition|Application|Runtime|Boundary|Protocols)/') {
            $Problems.Add("$Position 中立合同依赖实现 $Include")
        }
        if ($Relative -match '^Prism/Runtime/' -and
            ($Include -match '^Prism/(Composition|Application)/' -or
             $Include -match '^Prism/Protocols/(?!Common/|Quic/)')) {
            $Problems.Add("$Position Runtime 依赖协议/装配实现 $Include")
        }
        if ($Relative -match '^Prism/Boundary/' -and
            ($Include -match '^Prism/(Composition|Application)/' -or
             $Include -match '^Prism/Protocols/(?!Common/|Quic/)')) {
            $Problems.Add("$Position Boundary 依赖协议/装配实现 $Include")
        }
    }
}

# 用户规定的测试布局与生产 header-only 门禁一起检查，不编译或改写文件。
$TestLayoutRoot = Join-Path $RepoRoot 'tests/Prism'
$TestLayoutFiles = @(Get-ChildItem -LiteralPath $TestLayoutRoot -Recurse -File)
foreach ($TestFile in $TestLayoutFiles) {
    $TestRelative = [IO.Path]::GetRelativePath($TestLayoutRoot, $TestFile.FullName).Replace('\', '/')
    # Go reference clients keep their ecosystem package and source-file names.
    # C++ Prism test modules continue to follow the repository PascalCase rule.
    $IsGoReferenceTree = $TestRelative.StartsWith('Integration/Go/')
    if (-not $IsGoReferenceTree) {
        $Parts = $TestRelative.Split('/')
        for ($PartIndex = 0; $PartIndex -lt $Parts.Length - 1; ++$PartIndex) {
            if ($Parts[$PartIndex] -cnotmatch '^[A-Z][A-Za-z0-9]*$') {
                $Problems.Add("tests/Prism/$TestRelative 目录未使用 PascalCase: $($Parts[$PartIndex])")
            }
        }
        if ($TestFile.Name -cne 'CMakeLists.txt' -and
            [IO.Path]::GetFileNameWithoutExtension($TestFile.Name) -cnotmatch '^[A-Z][A-Za-z0-9]*$') {
            $Problems.Add("tests/Prism/$TestRelative 文件名未使用 PascalCase")
        }
    }
    if ($TestFile.Extension -in '.cpp', '.hpp', '.h', '.cc', '.cxx') {
        $TestLines = [IO.File]::ReadAllLines($TestFile.FullName)
        if ($TestLines.Length -gt 800) {
            $Problems.Add("tests/Prism/$TestRelative`: $($TestLines.Length) 行超过测试文件 800 行上限")
        }
        if ($TestFile.Extension -in '.h', '.cc', '.cxx') {
            $Problems.Add("tests/Prism/$TestRelative 测试实现只使用 CPP，共享封装只使用 HPP")
        }
        if ($TestFile.Extension -eq '.hpp') {
            $TestText = [IO.File]::ReadAllText($TestFile.FullName)
            if ($TestText -match '(?m)^\s*(?:TEST|TEST_F|TEST_P|TYPED_TEST|TYPED_TEST_P)\s*\(') {
                $Problems.Add("tests/Prism/$TestRelative 将 GoogleTest 用例正文放入共享 HPP")
            }
        }
    }
}

if ($Problems.Count -ne 0) {
    $Problems | ForEach-Object { Write-Output $_ }
    Write-Output "Prism contract gate FAILED: $($Problems.Count) 个源码问题"
    exit 1
}
Write-Output "Prism contract gate passed: $($Headers.Count) headers, $($Consumers.Count) source consumers, 0 production implementations; include directions, exact path case, retired interfaces and $($TestLayoutFiles.Count) test layout files checked"
exit 0
