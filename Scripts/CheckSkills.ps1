param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$SkillsRoot = Join-Path $RepositoryRoot '.claude\skills'
$ExpectedNames = @(
    'analyze-module',
    'archive-bug',
    'audit-memory',
    'bench-perf',
    'co-lifecycle-audit',
    'concurrency-audit',
    'coroutine-audit',
    'crypto-audit',
    'debug-cpp',
    'deepen-wiki',
    'dpi-audit',
    'draw-flowchart',
    'enforce-coding',
    'error-chain-audit',
    'harness-engineering',
    'leak-audit',
    'map-config',
    'mux-audit',
    'parse-proxylog',
    'pool-audit',
    'probe-audit',
    'protocol-handler',
    'replay-audit',
    'review-test',
    'security-audit',
    'traffic-audit',
    'tunnel-audit',
    'write-test'
)

$Failures = [System.Collections.Generic.List[string]]::new()

if (-not (Test-Path -LiteralPath $SkillsRoot -PathType Container)) {
    $Failures.Add("Missing skill root: $SkillsRoot")
}
else {
    $Directories = @(Get-ChildItem -LiteralPath $SkillsRoot -Directory | Where-Object {
        Test-Path -LiteralPath (Join-Path $_.FullName 'SKILL.md') -PathType Leaf
    })
    $ActualNames = @($Directories | ForEach-Object Name | Sort-Object)
    $ExpectedSorted = @($ExpectedNames | Sort-Object)

    foreach ($Name in $ExpectedSorted) {
        if ($Name -notin $ActualNames) {
            $Failures.Add("Missing skill directory: $Name")
        }
    }
    foreach ($Name in $ActualNames) {
        if ($Name -notin $ExpectedSorted) {
            $Failures.Add("Unexpected skill directory: $Name")
        }
    }

    foreach ($Directory in $Directories) {
        $SkillFile = Join-Path $Directory.FullName 'SKILL.md'
        if (-not (Test-Path -LiteralPath $SkillFile -PathType Leaf)) {
            $Failures.Add("Missing SKILL.md: $($Directory.Name)")
            continue
        }

        $Content = Get-Content -LiteralPath $SkillFile -Raw
        if ($Content -notmatch '(?ms)^---\s*\r?\n.*?^---\s*\r?\n') {
            $Failures.Add("Missing frontmatter: $SkillFile")
        }

        $NameMatch = [regex]::Match($Content, '(?m)^name:\s*([a-z0-9]+(?:-[a-z0-9]+)*)\s*$')
        if (-not $NameMatch.Success) {
            $Failures.Add("Invalid or missing skill name: $SkillFile")
        }
        elseif ($NameMatch.Groups[1].Value -ne $Directory.Name) {
            $Failures.Add("Directory/name mismatch: $SkillFile")
        }

        if ($Content -notmatch '(?m)^description:\s*\S+') {
            $Failures.Add("Missing description: $SkillFile")
        }

        foreach ($Pattern in @(
            '\.agents[\\/]skills',
            'H:/wiki',
            'src/project',
            'pipeline/protocols',
            'forward_add_test',
            'scaffold_harness_docs\.py',
            'pre-exec-cleanup'
        )) {
            if ($Content -match $Pattern) {
                $Failures.Add("Stale or forbidden reference '$Pattern': $SkillFile")
            }
        }
    }

    $ExtraFiles = @(Get-ChildItem -LiteralPath $SkillsRoot -Recurse -File | Where-Object Name -ne 'SKILL.md')
    foreach ($File in $ExtraFiles) {
        $Failures.Add("Untracked skill support file: $($File.FullName)")
    }

    $PythonFiles = @(Get-ChildItem -LiteralPath $SkillsRoot -Recurse -File -Filter '*.py')
    foreach ($File in $PythonFiles) {
        $Failures.Add("Python skill file is not allowed: $($File.FullName)")
    }
}

$LegacyRoot = Join-Path $RepositoryRoot '.agents\skills'
if (Test-Path -LiteralPath $LegacyRoot -PathType Container) {
    $LegacyFiles = @(Get-ChildItem -LiteralPath $LegacyRoot -Recurse -File)
    if ($LegacyFiles.Count -gt 0) {
        $Failures.Add("Legacy skill tree still contains files: $LegacyRoot")
    }
}

$RootRules = @(
    (Join-Path $RepositoryRoot 'AGENTS.md'),
    (Join-Path $RepositoryRoot 'CLAUDE.md')
)
foreach ($RulesFile in $RootRules) {
    if (Test-Path -LiteralPath $RulesFile -PathType Leaf) {
        $RulesContent = Get-Content -LiteralPath $RulesFile -Raw
        if ($RulesContent -match '\.agents[\\/]skills') {
            $Failures.Add("Legacy skill reference: $RulesFile")
        }
    }
}

if ($Failures.Count -gt 0) {
    $Failures | ForEach-Object { "FAIL: $_" }
    exit 1
}

"OK: $($ExpectedNames.Count) canonical skills validated"
