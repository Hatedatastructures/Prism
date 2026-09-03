Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Invoke-Interop.ps1') -LibraryOnly

function Assert-Equal([object]$Expected, [object]$Actual, [string]$Message) {
    if ($Expected -ne $Actual) {
        throw "$Message. Expected '$Expected', got '$Actual'."
    }
}

Assert-Equal 'pass' (Get-InteropStatus -ExitCode 0 -Output 'PASS: echo') 'zero exit is pass'
Assert-Equal 'protocol-failure' (Get-InteropStatus -ExitCode 1 -Output 'FAIL: protocol handshake rejected') 'protocol failure marker'
Assert-Equal 'implementation-mismatch' (Get-InteropStatus -ExitCode 1 -Output 'FAIL: echo mismatch') 'mismatch marker'
Assert-Equal 'environment-unavailable' (Get-InteropStatus -ExitCode 127 -Output 'command not found') 'missing command exit'
Assert-Equal 'blocked-production-prerequisite' (Get-InteropStatus -ExitCode 0 -Output '' -BlockedProductionPrerequisite) 'blocked prerequisite wins'

$result = New-InteropResult -Protocol 'ss2022' -Direction 'go-server-cpp-client' `
    -Scenario 'echo' -Implementation 'sing-shadowsocks-v0.2.12' -Commit 'deadbeef' `
    -Platform 'windows-amd64' -Status 'pass' -ExitCode 0 -Command 'test command' `
    -Artifacts @('stdout.log', 'stderr.log')
Assert-Equal 'ss2022' $result.protocol 'result protocol'
Assert-Equal 'go-server-cpp-client' $result.direction 'result direction'
Assert-Equal 2 $result.artifacts.Count 'result artifacts'

Write-Output 'PASS: InteropRunner classifier tests'
