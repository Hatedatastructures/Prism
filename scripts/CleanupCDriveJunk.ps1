[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FreeGb {
    $drive = Get-PSDrive -Name C
    return [math]::Round($drive.Free / 1GB, 2)
}

function Get-PathSizeBytes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [int64]0
    }

    $sum = (Get-ChildItem -LiteralPath $Path -Force -File -Recurse -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum

    if ($null -eq $sum) {
        return [int64]0
    }

    return [int64]$sum
}

function Format-Gb {
    param(
        [Parameter(Mandatory = $true)]
        [int64]$Bytes
    )

    return ('{0:N2} GB' -f ($Bytes / 1GB))
}

$protectedPaths = @(
    'C:\Users\C1373\.codex',
    'C:\Windows\WinSxS',
    'C:\ProgramData\NVIDIA Corporation\NVIDIA App\UpdateFramework',
    'C:\Users\C1373\CodexQuarantine_20260921\bJDBA',
    'C:\Users\C1373\CodexQuarantine_20260921\ServiceBackups'
)

$targets = @(
    'C:\Users\C1373\CodexQuarantine_20260921\vscode-cpptools',
    'C:\Users\C1373\CodexQuarantine_20260921\go-build',
    'C:\Users\C1373\CodexQuarantine_20260921\Temp',
    'C:\Users\C1373\AppData\Local\Microsoft\vscode-cpptools\ipch',
    'C:\Users\C1373\.gradle\caches',
    'C:\Users\C1373\go\pkg',
    'C:\Users\C1373\AppData\Local\npm-cache\_npx',
    'C:\Users\C1373\AppData\Local\Temp'
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
$isAdmin = $principal.IsInRole($adminRole)
$isWhatIf = $WhatIfPreference -eq $true
if (-not $isAdmin -and -not $isWhatIf) {
    try {
        $scriptPath = $PSCommandPath
        $workingDirectory = Split-Path -Parent $scriptPath
        $hostExecutable = Join-Path $PSHOME 'pwsh.exe'
        if (-not (Test-Path -LiteralPath $hostExecutable)) {
            $hostExecutable = Join-Path $PSHOME 'powershell.exe'
        }
        if (-not (Test-Path -LiteralPath $hostExecutable)) {
            throw 'Could not locate a PowerShell executable for UAC relaunch.'
        }
        Start-Process -FilePath $hostExecutable `
            -Verb RunAs `
            -WorkingDirectory $workingDirectory `
            -ArgumentList @('-NoProfile', '-File', ('"{0}"' -f $scriptPath)) | Out-Null
        Write-Host 'UAC elevation requested. The elevated cleanup process will continue separately.'
        return
    }
    catch {
        throw ('Administrator privileges are required, and the UAC request failed or was cancelled: ' + $_.Exception.Message)
    }
}
if (-not $isAdmin -and $isWhatIf) {
    Write-Warning 'Preview mode is running without administrator privileges. Some size reads may be incomplete.'
}

foreach ($target in $targets) {
    foreach ($protected in $protectedPaths) {
        $samePath = $target.Equals($protected, [StringComparison]::OrdinalIgnoreCase)
        $childPath = $target.StartsWith($protected + '\', [StringComparison]::OrdinalIgnoreCase)
        if ($samePath -or $childPath) {
            throw "Safety check failed: target overlaps protected path: $target"
        }
    }
}

$beforeFreeGb = Get-FreeGb
Write-Host "C drive free space before cleanup: $beforeFreeGb GB"
Write-Host 'Protected paths:'
$protectedPaths | ForEach-Object { Write-Host "  KEEP $_" }

$results = [System.Collections.Generic.List[object]]::new()
foreach ($target in $targets) {
    if (-not (Test-Path -LiteralPath $target)) {
        $results.Add([pscustomobject]@{
                Path = $target
                Status = 'Absent'
                Before = '0.00 GB'
                After = '0.00 GB'
                Error = ''
            })
        continue
    }

    $beforeBytes = Get-PathSizeBytes -Path $target
    $status = 'Skipped'
    $errorText = ''

    if ($PSCmdlet.ShouldProcess($target, 'Remove recursively')) {
        try {
            Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction Stop
            $status = 'Deleted'
        }
        catch {
            $status = 'Failed'
            $errorText = $_.Exception.Message
        }
    }

    $afterBytes = Get-PathSizeBytes -Path $target
    $results.Add([pscustomobject]@{
            Path = $target
            Status = $status
            Before = Format-Gb -Bytes $beforeBytes
            After = Format-Gb -Bytes $afterBytes
            Error = $errorText
        })
}

if ($PSCmdlet.ShouldProcess('C:\$Recycle.Bin', 'Clear the C drive recycle bin')) {
    try {
        Clear-RecycleBin -DriveLetter C -Force -ErrorAction Stop
        $results.Add([pscustomobject]@{
                Path = 'C:\$Recycle.Bin'
                Status = 'Cleared'
                Before = 'Not measured'
                After = 'Not measured'
                Error = ''
            })
    }
    catch {
        $results.Add([pscustomobject]@{
                Path = 'C:\$Recycle.Bin'
                Status = 'Failed'
                Before = 'Not measured'
                After = 'Not measured'
                Error = $_.Exception.Message
            })
    }
}

$results | Format-Table -AutoSize
$afterFreeGb = Get-FreeGb
$deltaGb = [math]::Round($afterFreeGb - $beforeFreeGb, 2)
Write-Host "C drive free space after cleanup: $afterFreeGb GB"
Write-Host "Free-space change: $deltaGb GB"
