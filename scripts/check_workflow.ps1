# check-workflow.ps1 - lightweight workflow and embedded-shell gate
# Usage: pwsh scripts/check_workflow.ps1 [-WorkflowPath <path>]

[CmdletBinding()]
param(
    [string]$WorkflowPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $WorkflowPath) {
    $WorkflowPath = Join-Path (Split-Path -Parent $PSScriptRoot) ".github/workflows/build.yml"
}

if (-not (Test-Path -LiteralPath $WorkflowPath -PathType Leaf)) {
    Write-Error "Workflow not found: $WorkflowPath"
    exit 1
}

$Lines = @(Get-Content -LiteralPath $WorkflowPath -Encoding UTF8)
$Problems = [System.Collections.Generic.List[string]]::new()

function Get-Indent([string]$Line) {
    return $Line.Length - $Line.TrimStart().Length
}

function Get-RunBlock([int]$RunLineIndex) {
    $RunIndent = Get-Indent $Lines[$RunLineIndex]
    $Content = [System.Collections.Generic.List[string]]::new()
    $End = $RunLineIndex
    for ($Index = $RunLineIndex + 1; $Index -lt $Lines.Count; ++$Index) {
        $Raw = $Lines[$Index]
        if ($Raw.Trim().Length -gt 0 -and (Get-Indent $Raw) -le $RunIndent) {
            break
        }
        $End = $Index
        if ($Raw.Trim().Length -eq 0) {
            $Content.Add("")
            continue
        }
        $ContentIndent = [Math]::Min($Raw.Length, $RunIndent + 2)
        $Content.Add($Raw.Substring($ContentIndent))
    }
    return [pscustomobject]@{
        Start = $RunLineIndex
        End = $End
        Indent = $RunIndent
        Script = ($Content -join "`n")
    }
}

$StepNames = @{}
$CurrentStep = ""
$RunBlocks = [System.Collections.Generic.List[object]]::new()

for ($Index = 0; $Index -lt $Lines.Count; ++$Index) {
    $Line = $Lines[$Index]
    if ($Line -match '^\s*-\s+name:\s*(.+?)\s*$') {
        $CurrentStep = $Matches[1]
        $StepNames[$Index] = $CurrentStep
        continue
    }

    if ($Line -match '^\s*run:\s*\|\s*$') {
        $RunBlock = Get-RunBlock $Index
        $Step = ""
        for ($StepIndex = $Index - 1; $StepIndex -ge 0; --$StepIndex) {
            if ($StepNames.ContainsKey($StepIndex)) {
                $Step = $StepNames[$StepIndex]
                break
            }
        }
        $RunBlocks.Add([pscustomobject]@{
            Block = $RunBlock
            Step = $Step
        })
        continue
    }

    if ($Line -match '^\s*run:\s*[^|].*$') {
        $RunIndent = Get-Indent $Line
        for ($Next = $Index + 1; $Next -lt $Lines.Count; ++$Next) {
            if ($Lines[$Next].Trim().Length -eq 0) {
                continue
            }
            if ((Get-Indent $Lines[$Next]) -gt $RunIndent -and
                $Lines[$Next].Trim() -in @('}', 'fi')) {
                $Problems.Add("Line $($Next + 1): shell terminator '$($Lines[$Next].Trim())' is outside the preceding run block")
            }
            break
        }
    }
}

if ($RunBlocks.Count -eq 0) {
    $Problems.Add("No literal run blocks found")
}

foreach ($Entry in $RunBlocks) {
    $Block = $Entry.Block
    $Step = $Entry.Step
    if ($Step -eq "Run Tests" -and $Block.Script.Trim().Length -eq 0) {
        $Problems.Add("Run Tests has an empty literal run block")
        continue
    }

    if ($Step -eq "Run Tests") {
        if ($Block.Script -match '(?m)^\s*if\s*\([^\r\n]*\)\s*\{') {
            $Tokens = $null
            $ParseErrors = $null
            [System.Management.Automation.Language.Parser]::ParseInput(
                $Block.Script, [ref]$Tokens, [ref]$ParseErrors) | Out-Null
            if ($ParseErrors.Count -gt 0) {
                $Problems.Add("$Step PowerShell parse failed: $($ParseErrors[0].Message)")
            }
        }

        if ($Block.Script -match '(?m)^\s*if\s+\[') {
            $Bash = Get-Command bash -ErrorAction SilentlyContinue
            if (-not $Bash) {
                $Problems.Add("$Step Bash validation unavailable: bash was not found")
            } else {
                & $Bash.Source -n -c $Block.Script
                if ($LASTEXITCODE -ne 0) {
                    $Problems.Add("$Step Bash parse failed with exit code $LASTEXITCODE")
                }
            }
        }
    }
}

$StepIndentSet = @($Lines | Where-Object { $_ -match '^\s*-\s+name:' } | ForEach-Object { Get-Indent $_ } | Sort-Object -Unique)
if ($StepIndentSet.Count -gt 1) {
    $Problems.Add("Workflow step indentation is inconsistent: $($StepIndentSet -join ', ')")
}

if ($Problems.Count -gt 0) {
    Write-Host "Workflow gate FAILED:" -ForegroundColor Red
    $Problems | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    exit 1
}

Write-Host "Workflow gate passed: $($RunBlocks.Count) literal run blocks checked"
exit 0
