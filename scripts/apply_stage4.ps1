# apply_stage4.ps1 - 阶段4标识符迁移应用器（幂等，可重复执行）
# 用法: pwsh -File scripts/apply_stage4.ps1
param()
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$generic = @('data','size','begin','end','empty','get','put','back','front','pop','push','wait','open','close','stop','start','read','write','bind','send','recv','reset','swap','clear','count','find','insert','erase','key','value','type','name','path','text','time','state','index','buf','len','pos','ec','ok')

$entries = Get-Content (Join-Path $root "scripts/migration_stage4_inventory.txt") -Encoding UTF8
$list = New-Object System.Collections.Generic.List[object]
foreach($e in $entries){
    $parts = $e -split "`t"
    if($parts.Count -lt 3){ continue }
    $sym = $parts[2]
    if($generic -contains $sym){ continue }
    $segs = ($sym.TrimEnd('_') -split '_') | Where-Object { $_ }
    if(-not $segs){ continue }
    $sb = New-Object System.Text.StringBuilder
    foreach($s in $segs){ [void]$sb.Append($s.Substring(0,1).ToUpper() + $s.Substring(1)) }
    $new = $sb.ToString()
    if($sym.EndsWith('_')){ $new += '_' }
    if(-not $new){ continue }
    [void]$list.Add([pscustomobject]@{ Sym=$sym; New=$new; File=($parts[1] -replace '/','\'); Len=$sym.Length })
}
$list = $list | Sort-Object Len -Descending
Write-Host "映射条目: $($list.Count)"

$grouped = $list | Group-Object -Property File
$changed = 0
foreach($g in $grouped){
    $fp = Join-Path $root $g.Name
    if(-not (Test-Path $fp)){ continue }
    $t = Get-Content $fp -Raw -Encoding UTF8
    $orig = $t
    foreach($i in $g.Group){
        if($i.Sym -and $i.New){ $t = $t.Replace($i.Sym, $i.New) }
    }
    if($t -ne $orig){
        Set-Content $fp -Value $t -NoNewline -Encoding UTF8
        $changed++
    }
}
Write-Host "本轮修改文件: $changed"
