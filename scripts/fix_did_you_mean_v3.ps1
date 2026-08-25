# fix_did_you_mean_v3.ps1 - 确定性映射优先 + GCC 建议兜底
param([string]$LogPath = "build\stage4_harvest2.log")
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot

# 载入确定性映射（old -> new），长名优先由调用侧保证
$detMap = @{}
Get-Content (Join-Path $root "scripts\stage4_rename_pairs.txt") -Encoding UTF8 | ForEach-Object {
    $p = $_ -split "`t"
    if($p.Count -eq 2){ $detMap[$p[0]] = $p[1] }
}
Write-Host "确定性映射: $($detMap.Count)"

$log = Get-Content (Join-Path $root $LogPath) -Encoding UTF8 -Raw
$pairs = [regex]::Matches($log, "I:[/\\]code[/\\]Prism[/\\](tests[^\r\n ]*?):\d+:\d+: error: ([^\r\n]+)")
Write-Host "错误对: $($pairs.Count)"

$grouped = @{}
$fixedDet = 0; $fixedSug = 0; $skipped = 0
foreach($m in $pairs){
    $file = $m.Groups[1].Value
    $msg = $m.Groups[2].Value
    $wrong = $null; $right = $null
    if($msg -match "(?m)^'(\w+)' (?:was not declared|is not declared|does not name a type)"){
        $wrong = $Matches[1]
        if($msg -match "did you mean '(\w+)'"){ $right = $Matches[1] }
    }
    elseif($msg -match "has no member named '(\w+)'"){
        $wrong = $Matches[1]
        if($msg -match "did you mean '(\w+)'"){ $right = $Matches[1] }
    }
    elseif($msg -match "is not a member of[^;]*?'(\w+)'"){
        $wrong = $Matches[1]
        if($msg -match "did you mean '(\w+)'"){ $right = $Matches[1] }
    }
    elseif($msg -match "'(\w+)' in namespace '[^']*' does not name a type.*?did you mean '(\w+)'"){
        $wrong = $Matches[1]; $right = $Matches[2]
    }
    if(-not $wrong){ continue }

    # 确定性映射优先
    if($detMap.ContainsKey($wrong)){ $target = $detMap[$wrong]; $src='DET' }
    elseif($right -and ($wrong -cne $right)){ $target = $right; $src='SUG' }
    else { $skipped++; continue }

    if(-not $grouped.ContainsKey($file)){ $grouped[$file] = New-Object System.Collections.Generic.List[object] }
    [void]$grouped[$file].Add([pscustomobject]@{ Wrong=$wrong; Right=$target })
    if($src -eq 'DET'){ $fixedDet++ } else { $fixedSug++ }
}
Write-Host "确定性: $fixedDet  建议: $fixedSug  跳过: $skipped  文件: $($grouped.Count)"

$applied = 0
foreach($file in $grouped.Keys){
    $fp = Join-Path $root ($file -replace '/','\')
    if(-not (Test-Path $fp)){ continue }
    $t = Get-Content $fp -Raw -Encoding UTF8
    $orig = $t
    # 同文件内同一 wrong 只应有单一 target；若冲突取第一个并告警
    $seen = @{}
    foreach($i in $grouped[$file]){
        if($seen.ContainsKey($i.Wrong)){
            if($seen[$i.Wrong] -ne $i.Right){ Write-Host "⚠ 冲突 $($file): $($i.Wrong) => $($seen[$i.Wrong]) / $($i.Right)，跳过后者" }
            continue
        }
        $seen[$i.Wrong] = $i.Right
        $t = [regex]::new("\b" + [regex]::Escape($i.Wrong) + "\b").Replace($t, $i.Right)
    }
    if($t -ne $orig){ Set-Content $fp -Value $t -NoNewline -Encoding UTF8; $applied++ }
}
Write-Host "应用文件数: $applied"
