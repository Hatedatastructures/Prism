# Preview 正式源码结构与模块方向门禁；不构建、不改写仓库。
param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Stop'
$PreviewRoot = Join-Path $RepoRoot 'Preview'
$Problems = [Collections.Generic.List[string]]::new()
$Headers = @(Get-ChildItem -LiteralPath $PreviewRoot -Recurse -File -Filter '*.hpp')
$FilePaths = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
Get-ChildItem -LiteralPath $PreviewRoot -Recurse -File | ForEach-Object {
    $RelativePath = [IO.Path]::GetRelativePath($RepoRoot, $_.FullName).Replace('\', '/')
    $FilePaths.Add($RelativePath, $RelativePath)
}
$Consumers = [Collections.Generic.List[IO.FileInfo]]::new()
foreach ($Header in $Headers) { $Consumers.Add($Header) }
foreach ($TestRoot in @('tests/Preview', 'tests/Experiments/Preview')) {
    $TestPath = Join-Path $RepoRoot $TestRoot
    if (Test-Path -LiteralPath $TestPath -PathType Container) {
        Get-ChildItem -LiteralPath $TestPath -Recurse -File |
            Where-Object { $_.Extension -in '.hpp', '.h', '.cpp', '.cc', '.cxx' } |
            ForEach-Object { $Consumers.Add($_) }
    }
}
$Implementations = @(Get-ChildItem -LiteralPath $PreviewRoot -Recurse -File |
    Where-Object { $_.Extension -in '.cpp', '.cc', '.cxx' })
foreach ($Implementation in $Implementations) {
    $Problems.Add("生产实现扩展名未退役: $($Implementation.FullName)")
}

$RetiredIncludes = @(
    'Preview/Runtime/Contract/DataPlane.hpp',
    'Preview/Runtime/Contract/Handler.hpp',
    'Preview/Composition/Adapters/TypedResult.hpp',
    'Preview/Composition/Adapters/DataPlane.hpp',
    'Preview/Composition/Adapters/ProtocolAdapter.hpp',
    'Preview/Composition/Adapters/DatagramService.hpp',
    'Preview/Composition/Adapters/Socks5Factory.hpp',
    'Preview/Composition/UdpService.hpp',
    'Preview/Composition/UdpServiceLogging.hpp',
    'Preview/Composition/Settings/Json.hpp',
    'Preview/Composition/Settings/Loader.hpp',
    'Preview/Runtime/Front/UdpFront.hpp',
    'Preview/Runtime/Front/QuicFront.hpp',
    'Preview/Foundation/Utility/Account/Directory.hpp',
    'Preview/Foundation/Utility/Account/Authenticator.hpp',
    'Preview/Foundation/Utility/Coroutine/Registry.hpp'
)

foreach ($RetiredPath in $RetiredIncludes) {
    if ($FilePaths.ContainsKey($RetiredPath)) {
        $Problems.Add("已要求退役的生产源码仍存在: $RetiredPath")
    }
}
foreach ($RelativePath in $FilePaths.Values) {
    if ($RelativePath -match '^Preview/(Ingress|Runtime/Front|Composition/Api|Scheduler|Net/Route|Net/Outbound)/' -and
        [IO.Path]::GetExtension($RelativePath) -in '.hpp', '.h', '.cpp', '.cc', '.cxx') {
        $Problems.Add("已要求退役的生产目录仍公开源码: $RelativePath")
    }
}

foreach ($Header in $Consumers) {
    $Relative = [IO.Path]::GetRelativePath($RepoRoot, $Header.FullName).Replace('\', '/')
    $Lines = [IO.File]::ReadAllLines($Header.FullName)
    if ($Relative.StartsWith('Preview/') -and $Lines.Length -gt 600) {
        $Problems.Add("$Relative`: $($Lines.Length) 行超过 600")
    }
    for ($Index = 0; $Index -lt $Lines.Length; ++$Index) {
        if ($Lines[$Index] -notmatch '^\s*#\s*include\s*[<"](Preview/[^>"]+)[>"]') {
            continue
        }
        $Include = $Matches[1]
        $Position = "$Relative`:$($Index + 1)"
        if (!$FilePaths.ContainsKey($Include)) {
            $Problems.Add("$Position 引用不存在的生产文件 $Include")
        }
        elseif ($FilePaths[$Include] -cne $Include) {
            $Problems.Add("$Position include大小写与真实路径不一致: $Include -> $($FilePaths[$Include])")
        }
        if ($RetiredIncludes -contains $Include -or
            $Include -match '^Preview/(Ingress|Runtime/Front|Composition/Api|Scheduler|Net/Route|Net/Outbound)/') {
            $Problems.Add("$Position 仍引用已要求退役的接口 $Include")
        }
        if ($Relative -match '^Preview/Protocols/' -and
            $Include -match '^Preview/(Composition|Application|Runtime)/') {
            $Problems.Add("$Position 协议反向依赖 $Include")
        }
        if ($Relative -match '^Preview/Contract/' -and
            $Include -match '^Preview/(Composition|Application|Runtime|Boundary|Protocols)/') {
            $Problems.Add("$Position 中立合同依赖实现 $Include")
        }
        if ($Relative -match '^Preview/Runtime/' -and
            ($Include -match '^Preview/(Composition|Application)/' -or
             $Include -match '^Preview/Protocols/(?!Common/|Quic/)')) {
            $Problems.Add("$Position Runtime 依赖协议/装配实现 $Include")
        }
        if ($Relative -match '^Preview/Boundary/' -and
            ($Include -match '^Preview/(Composition|Application)/' -or
             $Include -match '^Preview/Protocols/(?!Common/|Quic/)')) {
            $Problems.Add("$Position Boundary 依赖协议/装配实现 $Include")
        }
    }
}

# 用户规定的测试布局与生产 header-only 门禁一起检查，不编译或改写文件。
$TestLayoutRoot = Join-Path $RepoRoot 'tests/Preview'
$TestLayoutFiles = @(Get-ChildItem -LiteralPath $TestLayoutRoot -Recurse -File)
foreach ($TestFile in $TestLayoutFiles) {
    $TestRelative = [IO.Path]::GetRelativePath($TestLayoutRoot, $TestFile.FullName).Replace('\', '/')
    $Parts = $TestRelative.Split('/')
    for ($PartIndex = 0; $PartIndex -lt $Parts.Length - 1; ++$PartIndex) {
        if ($Parts[$PartIndex] -cnotmatch '^[A-Z][A-Za-z0-9]*$') {
            $Problems.Add("tests/Preview/$TestRelative 目录未使用 PascalCase: $($Parts[$PartIndex])")
        }
    }
    if ($TestFile.Name -cne 'CMakeLists.txt' -and
        [IO.Path]::GetFileNameWithoutExtension($TestFile.Name) -cnotmatch '^[A-Z][A-Za-z0-9]*$') {
        $Problems.Add("tests/Preview/$TestRelative 文件名未使用 PascalCase")
    }
    if ($TestFile.Extension -in '.cpp', '.hpp', '.h', '.cc', '.cxx') {
        $TestLines = [IO.File]::ReadAllLines($TestFile.FullName)
        if ($TestLines.Length -gt 800) {
            $Problems.Add("tests/Preview/$TestRelative`: $($TestLines.Length) 行超过测试文件 800 行上限")
        }
        if ($TestFile.Extension -in '.h', '.cc', '.cxx') {
            $Problems.Add("tests/Preview/$TestRelative 测试实现只使用 CPP，共享封装只使用 HPP")
        }
        if ($TestFile.Extension -eq '.hpp') {
            $TestText = [IO.File]::ReadAllText($TestFile.FullName)
            if ($TestText -match '(?m)^\s*(?:TEST|TEST_F|TEST_P|TYPED_TEST|TYPED_TEST_P)\s*\(') {
                $Problems.Add("tests/Preview/$TestRelative 将 GoogleTest 用例正文放入共享 HPP")
            }
        }
    }
}

if ($Problems.Count -ne 0) {
    $Problems | ForEach-Object { Write-Output $_ }
    Write-Output "Preview contract gate FAILED: $($Problems.Count) 个源码问题"
    exit 1
}
Write-Output "Preview contract gate passed: $($Headers.Count) headers, $($Consumers.Count) source consumers, 0 production implementations; include directions, exact path case, retired interfaces and $($TestLayoutFiles.Count) test layout files checked"
exit 0
