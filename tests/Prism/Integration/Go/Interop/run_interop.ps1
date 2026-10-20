# SS2022 interop test orchestration
# Direction A: Go server (sing-shadowsocks v0.2.12) <- C++ common client
# Direction B: C++ common server <- Go client (sing-shadowsocks v0.2.12)
param(
    [Parameter(Mandatory = $true)][string]$CppClient,
    [Parameter(Mandatory = $true)][string]$CppServer,
    [Parameter(Mandatory = $true)][string]$GoServer,
    [Parameter(Mandatory = $true)][string]$GoClient
)

function Stop-Proc([System.Diagnostics.Process]$p) {
    if ($p -and -not $p.HasExited) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
}

function Wait-ProcessExit {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process,
        [ValidateRange(1, 60000)][int]$WaitMilliseconds = 10000
    )

    $Exited = $Process.WaitForExit($WaitMilliseconds)
    $ExitCode = $null
    if ($Exited) {
        $Process.Refresh()
        $ExitCode = $Process.ExitCode
    }
    return [pscustomobject]@{
        exited = $Exited
        exit_code = $ExitCode
    }
}

$goServerProc = $null
$cppServerProc = $null
try {
    # Direction A: Go server + C++ client
    $goServerProc = Start-Process -FilePath $GoServer -ArgumentList "127.0.0.1:19080" -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 800
    & $CppClient "127.0.0.1:19080"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "interop A (Go server <- C++ client) failed"
        exit 1
    }
    Stop-Proc $goServerProc
    $goServerProc = $null
    Start-Sleep -Milliseconds 300

    # Direction B: C++ server + Go client
    $cppServerProc = Start-Process -FilePath $CppServer -ArgumentList "127.0.0.1:19080" -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 800
    & $GoClient "127.0.0.1:19080"
    $goClientExitCode = $LASTEXITCODE
    $cppServerExit = Wait-ProcessExit -Process $cppServerProc
    if ($goClientExitCode -ne 0 -or -not $cppServerExit.exited -or $cppServerExit.exit_code -ne 0) {
        $cppServerStatus = if ($cppServerExit.exited) {
            "exit code $($cppServerExit.exit_code)"
        } else {
            'did not exit within 10000 ms'
        }
        throw ("interop B failed (Go client exit code {0}; C++ server {1})" -f `
            $goClientExitCode, $cppServerStatus)
    }
    Stop-Proc $cppServerProc
    $cppServerProc = $null
    Write-Output "PASS: ss2022 interop both directions"
    exit 0
}
finally {
    Stop-Proc $goServerProc
    Stop-Proc $cppServerProc
}
