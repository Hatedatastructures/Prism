# fix_did_you_mean.ps1 - 从构建日志提取 GCC 建议并按文件批量回填（幂等）
param([string]$LogPath = "build\stage4_harvest1.log")
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$log = Get-Content (Join-Path $root $LogPath) -Encoding UTF8 -Raw

$pairs = [regex]::Matches($log, "I:[/\\]code[/\\]Prism[/\\](tests[^\r\n ]*?):\d+:\d+: error: ([^\r\n]+)")
$map = @{}
foreach($m in $pairs){
    $file = $m.Groups[1].Value
    $msg = $m.Groups[2].Value
    if($msg -notmatch "did you mean '(\w+)'"){ continue }
    $right = $Matches[1]
    $wrong = $null
    if($msg -match "(?m)^'(\w+)' (?:was not declared|is not declared|does not name a type)"){ $wrong = $Matches[1] }
    elseif($msg -match "has no member named '(\w+)'"){ $wrong = $Matches[1] }
    elseif($msg -match "is not a member of[^;]*?'(\w+)'"){ $wrong = $Matches[1] }
    elseif($msg -match "in namespace '[^']*' does not name a type.*did you mean '(\w+)'"){ $wrong = $Matches[1] }
    elseif($msg -match "'(\w+)' is not a member"){ $wrong = $Matches[1] }
    if(-not $wrong -or $wrong -ceq $right){ continue }
    $k = "$file|$wrong"
    if($map.ContainsKey($k)){ if($map[$k] -ne $right){ $map[$k] = $null } } else { $map[$k] = $right }
}
Write-Host "配对总数: $($pairs.Count)，唯一映射: $($map.Count)"

$grouped = @{}
foreach($k in $map.Keys){
    if(-not $map[$k]){ continue }
    $parts = $k.Split('|')
    if(-not $grouped.ContainsKey($parts[0])){ $grouped[$parts[0]] = New-Object System.Collections.Generic.List[object] }
    [void]$grouped[$parts[0]].Add([pscustomobject]@{ Wrong=$parts[1]; Right=$map[$k] })
}
Write-Host "涉及文件: $($grouped.Count)"
$applied = 0
foreach($file in $grouped.Keys){
    $fp = Join-Path $root ($file -replace '/','\')
    if(-not (Test-Path $fp)){ continue }
    $t = Get-Content $fp -Raw -Encoding UTF8
    $orig = $t
    foreach($i in $grouped[$file]){
        if($i.Wrong -ceq $i.Right){ continue }
        $t = [regex]::new("\b" + [regex]::Escape($i.Wrong) + "\b").Replace($t, $i.Right)
    }
    if($t -ne $orig){ Set-Content $fp -Value $t -NoNewline -Encoding UTF8; $applied++ }
}
Write-Host "应用文件数: $applied"
