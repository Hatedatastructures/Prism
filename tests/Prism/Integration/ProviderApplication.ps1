param(
    [string]$RepoRoot='I:/code/Prism',
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Utf8=[Text.UTF8Encoding]::new($false)
$Owned=[Collections.Generic.List[object]]::new()
$Cases=[Collections.Generic.List[object]]::new()
$DynamicConfigurations=[Collections.Generic.List[object]]::new()
$LaunchFailures=[Collections.Generic.List[object]]::new()
$EvidenceFailures=[Collections.Generic.List[object]]::new()
$ExpectedCaseNames=@(
    'socks-tcp-1'
    'socks-tcp-2'
    'socks-tcp-3'
    'socks-bad-auth'
    'socks-postdial-refused'
    'socks-udp-control'
    'socks-bnd-socket-closed'
    'ss-tcp-account-1-1'
    'ss-tcp-account-1-2'
    'ss-tcp-account-1-3'
    'ss-udp-account-1'
    'ss-tcp-account-2-1'
    'ss-tcp-account-2-2'
    'ss-tcp-account-2-3'
    'ss-udp-account-2'
    'ss-tcp-bad-key'
    'ss-udp-bad-key'
    'negative-no-egress'
)
$Status='FAIL'
$MainCompleted=$false
$MainFailure=$null
$CleanupHealthy=$true
$ProcessInventoryCaptured=$false
$LiveDirectoryCleanupFailed=$false
$EvidenceTimeUtc=[DateTime]::UtcNow.ToString('o')
$StaticEvidence=$null
$SourceManifest=$null
$OutputDirectoryCanonical=$null
$RunDirectory=$null
$SourceManifestPath=$null
$EpochMarker=$null
$EvidenceBindingMarker=$null
$OwnedRecords=$null
$Fresh=$null
$ConfirmedPids=@()
$ConfirmedIdentities=@()
$UnverifiedProcessPids=@()
$InventoryIdentityMismatches=@()
$ProcessInventoryError=$null
$RemainingCount=-1
$CaseContractPassed=$false
$LiveDirectoryRemaining=$false
$FinalEvidenceTimeUtc=$null
$EnabledConfigurations=@()
$DisabledConfigurations=@()
$OperationsSummary=[ordered]@{
    Expected='unknown'
    Enabled=@()
    Disabled=@()
    AllDisabled=$false
    Configurations=@()
}
$CleanupEvidence=$null
$Provenance=$null
$ProvenanceWritten=$false
$FailureText=$null
$ResidualFailureText=$null
$ResidualLiveDirectories=@()
$ResidualFailurePath=$null
$ProcessIdentityEvidenceBoundary='Complete process identity requires PID, canonical executable path, StartTime, and CreationDate. Win32_Process.CreationDate is preferred; if CIM no longer sees a short-lived process, the retained Process object may supply MainModule.FileName and the kernel creation time exposed as Process.StartTime, recorded with an explicit source. If the process object also lost its executable path, the canonical launch artifact may supply PathSource=CanonicalLaunchArtifact, but only with a complete PID/StartTime/CreationDate snapshot and matching path/PID checks. If neither complete observation is available, owner registration remains failed and the case is not counted.'
$ProcessIdentityTimestampTolerance=[TimeSpan]::FromMilliseconds(1)
$ProcessIdentityTimestampToleranceTicks=[Int64]$ProcessIdentityTimestampTolerance.Ticks

function GetCanonicalPath($Path){
    if([string]::IsNullOrWhiteSpace([string]$Path)){throw 'Path must not be empty'}
    $FullPath=[IO.Path]::GetFullPath([string]$Path)
    $Root=[IO.Path]::GetPathRoot($FullPath)
    if([string]::IsNullOrEmpty($Root)){throw ('Path has no root: '+$Path)}
    if($FullPath.Length -gt $Root.Length){return $FullPath.TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)}
    return $Root
}
function TestCanonicalChild($Child,$Parent){
    $ChildCanonical=GetCanonicalPath $Child
    $ParentCanonical=GetCanonicalPath $Parent
    if($ChildCanonical-eq$ParentCanonical){return $false}
    $ParentRoot=GetCanonicalPath ([IO.Path]::GetPathRoot($ParentCanonical))
    $Prefix=if($ParentCanonical-eq$ParentRoot){$ParentCanonical}else{$ParentCanonical+[IO.Path]::DirectorySeparatorChar}
    return $ChildCanonical.StartsWith($Prefix,[StringComparison]::OrdinalIgnoreCase)
}

function GetDirectoryInfoSafe($Path,$AllowMissing){
    $Canonical=GetCanonicalPath $Path
    if(-not (Test-Path -LiteralPath $Canonical)){
        if($AllowMissing){return $null}
        throw ('Directory does not exist: '+$Canonical)
    }
    $Item=Get-Item -LiteralPath $Canonical -Force -ErrorAction Stop
    if($Item -isnot [IO.DirectoryInfo]){
        throw ('Expected DirectoryInfo: '+$Canonical)
    }
    $LinkTypeProperty=$Item.PSObject.Properties['LinkType']
    $LinkType=if($null-ne$LinkTypeProperty){[string]$LinkTypeProperty.Value}else{''}
    $IsReparse=(($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    if($IsReparse -or -not [string]::IsNullOrWhiteSpace($LinkType)){
        throw ('Refusing reparse/link directory: '+$Canonical+' LinkType='+$LinkType+' Attributes='+$Item.Attributes)
    }
    return $Item
}

function AssertNoReparsePointInPath($Path){
    $Current=GetCanonicalPath $Path
    while($true){
        if(Test-Path -LiteralPath $Current){$null=GetDirectoryInfoSafe $Current $false}
        $Root=GetCanonicalPath ([IO.Path]::GetPathRoot($Current))
        if($Current-eq$Root){break}
        $Parent=[IO.Directory]::GetParent($Current)
        if($null-eq$Parent){break}
        $Current=GetCanonicalPath $Parent
    }
}

function AssertOwnedRunDirectory($Path,$Token,$MarkerPath){
    $Canonical=GetCanonicalPath $Path
    $null=GetDirectoryInfoSafe $Canonical $false
    if(-not (TestCanonicalChild $Canonical $OutputDirectoryCanonical)){
        throw ('Run directory is outside this output directory: '+$Canonical)
    }
    $MarkerCanonical=GetCanonicalPath $MarkerPath
    if(-not (TestCanonicalChild $MarkerCanonical $Canonical)){
        throw ('Run marker is outside the run directory: '+$MarkerCanonical)
    }
    if(-not (Test-Path -LiteralPath $MarkerCanonical -PathType Leaf)){
        throw ('Run marker is missing: '+$MarkerCanonical)
    }
    if(-not [String]::Equals([IO.File]::ReadAllText($MarkerCanonical),[string]$Token,[StringComparison]::Ordinal)){
        throw ('Run marker does not match this invocation: '+$Canonical)
    }
    foreach($Item in @(Get-ChildItem -LiteralPath $Canonical -Force -Recurse -ErrorAction Stop)){
        $LinkTypeProperty=$Item.PSObject.Properties['LinkType']
        $LinkType=if($null-ne$LinkTypeProperty){[string]$LinkTypeProperty.Value}else{''}
        $IsReparse=(($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        if($IsReparse -or -not [string]::IsNullOrWhiteSpace($LinkType)){
            throw ('Refusing run cleanup through reparse/link item: '+$Item.FullName)
        }
    }
}

function GetUtcTimestamp($Value){
    if($null-eq$Value){throw 'Process timestamp is missing'}
    if($Value -is [DateTimeOffset]){return $Value.ToUniversalTime().ToString('o')}
    if($Value -is [DateTime]){return $Value.ToUniversalTime().ToString('o')}
    $Text=[string]$Value
    if([string]::IsNullOrWhiteSpace($Text)){throw 'Process timestamp is empty'}
    try{
        return ([DateTimeOffset]::Parse($Text,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)).ToUniversalTime().ToString('o')
    }catch{
        try{return ([System.Management.ManagementDateTimeConverter]::ToDateTime($Text)).ToUniversalTime().ToString('o')}
        catch{throw ('Unable to normalize process timestamp: '+$Text)}
    }
}

function GetProcessTimestampTicks($Value){
    if($null-eq$Value -or [string]::IsNullOrWhiteSpace([string]$Value)){return $null}
    try{
        $Normalized=GetUtcTimestamp $Value
        return [DateTimeOffset]::ParseExact($Normalized,'o',[Globalization.CultureInfo]::InvariantCulture).UtcDateTime.Ticks
    }catch{return $null}
}

function TestProcessTimestamp($Expected,$Actual){
    $ExpectedTicks=GetProcessTimestampTicks $Expected
    $ActualTicks=GetProcessTimestampTicks $Actual
    if($null-eq$ExpectedTicks -or $null-eq$ActualTicks){return $false}
    $Difference=[Int64]$ExpectedTicks-[Int64]$ActualTicks
    if($Difference-lt 0){$Difference=-$Difference}
    return $Difference-le $ProcessIdentityTimestampToleranceTicks
}

function NewProcessIdentity($Observed,$Candidate,$KnownExecutablePath){
    if($null-eq$Observed){throw 'Process identity observation is missing'}
    if($null-eq$Candidate){throw 'Process object is missing for identity observation'}
    $ProcessId=[int]$Observed.ProcessId
    if($ProcessId -le 0){throw ('Process identity has invalid PID: '+$ProcessId)}
    if([int]$Candidate.Id -ne $ProcessId){throw ('Process identity PID changed: expected='+$ProcessId+' actual='+$Candidate.Id)}
    $KnownCanonicalPath=$null
    if(-not [string]::IsNullOrWhiteSpace([string]$KnownExecutablePath)){$KnownCanonicalPath=GetCanonicalPath $KnownExecutablePath}
    $ExecutablePath=$null
    $PathSource='Win32_Process.ExecutablePath'
    $ExecutablePathProperty=$Observed.PSObject.Properties['ExecutablePath']
    try{if($null-ne$ExecutablePathProperty){$ExecutablePath=[string]$ExecutablePathProperty.Value}}catch{$ExecutablePath=$null}
    if([string]::IsNullOrWhiteSpace($ExecutablePath)){
        if($null-eq$KnownCanonicalPath){throw ('Process identity has no executable path for PID '+$ProcessId)}
        $ExecutablePath=$KnownCanonicalPath
        $PathSource='CanonicalLaunchArtifact'
    }else{
        $ExecutablePath=GetCanonicalPath $ExecutablePath
        if($null-ne$KnownCanonicalPath -and ![String]::Equals($ExecutablePath,$KnownCanonicalPath,[StringComparison]::OrdinalIgnoreCase)){
            throw ('Process identity executable path mismatch; expected='+$KnownCanonicalPath+' actual='+$ExecutablePath)
        }
    }
    $CreationDateProperty=$Observed.PSObject.Properties['CreationDate']
    if($null-eq$CreationDateProperty){throw ('Process identity has no CreationDate for PID '+$ProcessId)}
    $CreationDate=GetUtcTimestamp $CreationDateProperty.Value
    $StartTimeProperty=$Candidate.PSObject.Properties['StartTime']
    if($null-eq$StartTimeProperty){throw ('Process identity has no StartTime for PID '+$ProcessId)}
    $StartTime=GetUtcTimestamp $StartTimeProperty.Value
    return [PSCustomObject]@{
        Pid=$ProcessId
        Path=$ExecutablePath
        PathSource=$PathSource
        Start=$StartTime
        StartTime=$StartTime
        CreationDate=$CreationDate
        CreationDateSource='Win32_Process.CreationDate'
        IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary
    }
}

function NewProcessObjectIdentity($Candidate,$KnownExecutablePath){
    if($null-eq$Candidate){throw 'Process object is missing for early identity observation'}
    try{$Candidate.Refresh()}catch{}
    $CandidateExited=$false
    try{$CandidateExited=[bool]$Candidate.HasExited}catch{}
    $ProcessId=[int]$Candidate.Id
    if($ProcessId -le 0){throw ('Process object has invalid PID: '+$ProcessId)}
    $KnownCanonicalPath=$null
    if(-not [string]::IsNullOrWhiteSpace([string]$KnownExecutablePath)){$KnownCanonicalPath=GetCanonicalPath $KnownExecutablePath}
    $ExecutablePath=$null
    $PathSource='Process.MainModule.FileName'
    try{$ExecutablePath=[string]$Candidate.MainModule.FileName}catch{}
    if([string]::IsNullOrWhiteSpace($ExecutablePath)){
        try{
            $PathProperty=$Candidate.PSObject.Properties['Path']
            if($null-ne$PathProperty){
                $PathValue=[string]$PathProperty.Value
                if(-not [string]::IsNullOrWhiteSpace($PathValue)){$ExecutablePath=$PathValue;$PathSource='Process.Path'}
            }
        }catch{}
    }
    if([string]::IsNullOrWhiteSpace($ExecutablePath)){
        if($null-eq$KnownCanonicalPath){throw ('Process object has no executable path for PID '+$ProcessId)}
        $ExecutablePath=$KnownCanonicalPath
        $PathSource='CanonicalLaunchArtifact'
    }else{
        $ExecutablePath=GetCanonicalPath $ExecutablePath
        if($null-ne$KnownCanonicalPath -and ![String]::Equals($ExecutablePath,$KnownCanonicalPath,[StringComparison]::OrdinalIgnoreCase)){
            if(-not $CandidateExited){
                throw ('Process object executable path mismatch; expected='+$KnownCanonicalPath+' actual='+$ExecutablePath)
            }
            $FallbackStartTimeProperty=$Candidate.PSObject.Properties['StartTime']
            if($null-eq$FallbackStartTimeProperty){throw ('Process object has no StartTime for PID '+$ProcessId)}
            $FallbackStartTime=GetUtcTimestamp $FallbackStartTimeProperty.Value
            $FallbackCreationDate=$FallbackStartTime
            $FallbackCreationDateProperty=$Candidate.PSObject.Properties['CreationDate']
            if($null-ne$FallbackCreationDateProperty -and -not [string]::IsNullOrWhiteSpace([string]$FallbackCreationDateProperty.Value)){
                $FallbackCreationDate=GetUtcTimestamp $FallbackCreationDateProperty.Value
            }
            if($null-eq (GetProcessTimestampTicks $FallbackStartTime) -or $null-eq (GetProcessTimestampTicks $FallbackCreationDate)){
                throw ('Process object has incomplete timestamps for exited PID '+$ProcessId)
            }
            $ExecutablePath=$KnownCanonicalPath
            $PathSource='CanonicalLaunchArtifact'
        }
    }
    $StartTimeProperty=$Candidate.PSObject.Properties['StartTime']
    if($null-eq$StartTimeProperty){throw ('Process object has no StartTime for PID '+$ProcessId)}
    $StartTime=GetUtcTimestamp $StartTimeProperty.Value
    $CreationDate=$StartTime
    $CreationDateSource='System.Diagnostics.Process.StartTime (kernel process creation time)'
    $CreationDateProperty=$Candidate.PSObject.Properties['CreationDate']
    if($null-ne$CreationDateProperty -and -not [string]::IsNullOrWhiteSpace([string]$CreationDateProperty.Value)){
        $CreationDate=GetUtcTimestamp $CreationDateProperty.Value
        $CreationDateSource='Process.CreationDate'
    }
    return [PSCustomObject]@{
        Pid=$ProcessId
        Path=$ExecutablePath
        PathSource=$PathSource
        Start=$StartTime
        StartTime=$StartTime
        CreationDate=$CreationDate
        CreationDateSource=$CreationDateSource
        IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary
    }
}

function GetProcessIdentity($ProcessId,$Candidate,$KnownExecutablePath){
    if($null-eq$ProcessId -or [int]$ProcessId -le 0){throw 'Cannot observe process identity without a valid PID'}
    $EarlyIdentity=$null
    $EarlyError=$null
    try{$EarlyIdentity=NewProcessObjectIdentity $Candidate $KnownExecutablePath}catch{$EarlyError=[string]$_}
    if($null-ne$EarlyIdentity -and [int]$EarlyIdentity.Pid -ne [int]$ProcessId){
        throw ('Process identity PID changed: expected='+$ProcessId+' actual='+$EarlyIdentity.Pid)
    }
    $LastError=$null
    $CimObservationConflict=$false
    foreach($Delay in @(0,10,25)){
        if($Delay -gt 0){Start-Sleep -Milliseconds $Delay}
        try{
            $Observed=@(Get-CimInstance Win32_Process -Filter ('ProcessId = '+[int]$ProcessId) -ErrorAction Stop)
            if($Observed.Count -eq 0){
                $LastError='Win32_Process observation not found for PID '+$ProcessId
                continue
            }
            $Identity=NewProcessIdentity $Observed[0] $Candidate $KnownExecutablePath
            if($null-ne$EarlyIdentity -and -not (TestProcessIdentity $EarlyIdentity $Identity)){
                $CimObservationConflict=$true
                throw ('Process identity observations disagree for PID '+$ProcessId)
            }
            return $Identity
        }catch{$LastError=[string]$_}
    }
    if($CimObservationConflict){throw $LastError}
    if($null-ne$EarlyIdentity){return $EarlyIdentity}
    $Message='Process identity not found for PID '+$ProcessId
    if($null-ne$EarlyError){$Message+='; early process snapshot failed: '+$EarlyError}
    if($null-ne$LastError){$Message+='; CIM observation failed: '+$LastError}
    throw $Message
}

function GetCurrentProcessIdentity($ProcessId,$KnownExecutablePath){
    if($null-eq$ProcessId -or [int]$ProcessId -le 0){throw 'Cannot inventory process identity without a valid PID'}
    $Observed=@(Get-CimInstance Win32_Process -Filter ('ProcessId = '+[int]$ProcessId) -ErrorAction Stop)
    if($Observed.Count -eq 0){return $null}
    $Candidate=Get-Process -Id ([int]$ProcessId) -ErrorAction Stop
    return NewProcessIdentity $Observed[0] $Candidate $KnownExecutablePath
}

function TestProcessIdentity($Expected,$Actual){
    if(-not (TestCompleteProcessIdentity $Expected) -or -not (TestCompleteProcessIdentity $Actual)){return $false}
    if([int]$Expected.Pid -ne [int]$Actual.Pid){return $false}
    if(![String]::Equals([string]$Expected.Path,[string]$Actual.Path,[StringComparison]::OrdinalIgnoreCase)){return $false}
    if(-not (TestProcessTimestamp $Expected.StartTime $Actual.StartTime)){return $false}
    return TestProcessTimestamp $Expected.CreationDate $Actual.CreationDate
}

function TestCompleteProcessIdentity($Identity){
    if($null-eq$Identity -or $null-eq$Identity.Pid -or [int]$Identity.Pid -le 0){return $false}
    if([string]::IsNullOrWhiteSpace([string]$Identity.Path) -or
       [string]::IsNullOrWhiteSpace([string]$Identity.PathSource) -or
       [string]::IsNullOrWhiteSpace([string]$Identity.StartTime) -or
       [string]::IsNullOrWhiteSpace([string]$Identity.CreationDate) -or
       [string]::IsNullOrWhiteSpace([string]$Identity.CreationDateSource) -or
       [string]::IsNullOrWhiteSpace([string]$Identity.IdentityEvidenceBoundary)){return $false}
    return $null-ne (GetProcessTimestampTicks $Identity.StartTime) -and
        $null-ne (GetProcessTimestampTicks $Identity.CreationDate)
}

function GetProcessIdentityKey($Identity){
    if(-not (TestCompleteProcessIdentity $Identity)){throw 'Cannot key an incomplete process identity'}
    $StartTicks=GetProcessTimestampTicks $Identity.StartTime
    $CreationTicks=GetProcessTimestampTicks $Identity.CreationDate
    if($null-eq$StartTicks -or $null-eq$CreationTicks){throw 'Cannot key an incomplete process identity timestamp'}
    return ([string]$Identity.Pid+'|'+[string]$Identity.Path+'|'+[string]$StartTicks+'|'+[string]$CreationTicks)
}

function TestExitedProcessIdentity($P,$Entry){
    try{
        if($null-eq$P -or $null-eq$Entry){return $false}
        if($null-eq$Entry.Process -or ![object]::ReferenceEquals($Entry.Process,$P)){return $false}
        $ExitStart=GetUtcTimestamp $P.StartTime
        $ExitIdentity=[PSCustomObject]@{
            Pid=[int]$P.Id
            Path=$Entry.Path
            PathSource=$Entry.PathSource
            Start=$ExitStart
            StartTime=$ExitStart
            CreationDate=$Entry.CreationDate
            CreationDateSource=$Entry.CreationDateSource
            IdentityEvidenceBoundary=$Entry.IdentityEvidenceBoundary
        }
        return (TestProcessIdentity $Entry $ExitIdentity)
    }catch{return $false}
}

function GetLiveResidualDirectories($Root){
    $Residual=[Collections.Generic.List[string]]::new()
    foreach($Item in @(Get-ChildItem -LiteralPath $Root -Directory -Filter 'live-*' -Force -ErrorAction Stop)){
        $Canonical=GetCanonicalPath $Item.FullName
        if(-not (TestCanonicalChild $Canonical $Root)){
            throw ('Refusing live residual outside output directory: '+$Canonical)
        }
        $null=GetDirectoryInfoSafe $Canonical $false
        [void]$Residual.Add($Canonical)
    }
    return @($Residual.ToArray())
}

$OutputDirectoryCanonical=GetCanonicalPath $OutputDirectory
AssertNoReparsePointInPath $OutputDirectoryCanonical
if(Test-Path -LiteralPath $OutputDirectoryCanonical){
    $null=GetDirectoryInfoSafe $OutputDirectoryCanonical $false
}else{
    New-Item -ItemType Directory -Path $OutputDirectoryCanonical -ErrorAction Stop|Out-Null
    $null=GetDirectoryInfoSafe $OutputDirectoryCanonical $false
}
$OutputDirectory=$OutputDirectoryCanonical
try{
    $ResidualLiveDirectories=@(GetLiveResidualDirectories $OutputDirectoryCanonical)
    if($ResidualLiveDirectories.Count -gt 0){
        $ResidualFailureText='Provider18 residual failure: refusing to start because existing live-* directories remain under OutputRoot; retained evidence was not deleted. Residuals='+[string]::Join(';',$ResidualLiveDirectories)
        $ResidualFailurePath=Join-Path $OutputDirectoryCanonical ('residual-failure-'+[Guid]::NewGuid().ToString('N')+'.txt')
        [IO.File]::WriteAllText($ResidualFailurePath,$ResidualFailureText,$Utf8)
        $StableFailurePath=Join-Path $OutputDirectoryCanonical 'failure.txt'
        if(-not (Test-Path -LiteralPath $StableFailurePath -PathType Leaf)){
            [IO.File]::WriteAllText($StableFailurePath,$ResidualFailureText,$Utf8)
        }
        throw $ResidualFailureText
    }
}catch{
    if($null-eq$ResidualFailurePath){$ResidualFailurePath=Join-Path $OutputDirectoryCanonical ('residual-failure-'+[Guid]::NewGuid().ToString('N')+'.txt')}
    try{
        $ResidualFailureText=if($null-ne$ResidualFailureText){$ResidualFailureText}else{'Provider18 residual failure: unable to establish a clean OutputRoot before starting a new run. Error='+[string]$_}
        if(-not (Test-Path -LiteralPath $ResidualFailurePath -PathType Leaf)){
            [IO.File]::WriteAllText($ResidualFailurePath,$ResidualFailureText,$Utf8)
        }
        $StableFailurePath=Join-Path $OutputDirectoryCanonical 'failure.txt'
        if(-not (Test-Path -LiteralPath $StableFailurePath -PathType Leaf)){
            [IO.File]::WriteAllText($StableFailurePath,$ResidualFailureText,$Utf8)
        }
    }catch{}
    throw
}
$RunDirectory=GetCanonicalPath (Join-Path $OutputDirectoryCanonical ('live-'+[Guid]::NewGuid().ToString('N')))
if(-not (TestCanonicalChild $RunDirectory $OutputDirectoryCanonical)){
    throw ('Refusing non-child run directory: '+$RunDirectory)
}
AssertNoReparsePointInPath $RunDirectory
if(Test-Path -LiteralPath $RunDirectory){
    throw ('Refusing to reuse existing live directory: '+$RunDirectory)
}
New-Item -ItemType Directory -Path $RunDirectory -ErrorAction Stop|Out-Null
$null=GetDirectoryInfoSafe $RunDirectory $false
$RunMarkerToken=[Guid]::NewGuid().ToString('N')
$RunMarkerPath=Join-Path $RunDirectory '.provider18-run-marker'
[IO.File]::WriteAllText($RunMarkerPath,$RunMarkerToken,$Utf8)
$SourceManifestPath=Join-Path $OutputDirectory 'source-manifest.json'
function WriteJson($Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 30),$Utf8)}
function RecordEvidenceFailure($Stage,$ErrorRecord){
    try{
        $Message=if($null-ne$ErrorRecord){[string]$ErrorRecord}else{'unknown error'}
        [void]$EvidenceFailures.Add([ordered]@{Stage=[string]$Stage;Error=$Message})
    }catch{}
}
function TryWriteText($Path,$Text,$Stage){
    try{[IO.File]::WriteAllText($Path,[string]$Text,$Utf8);return $true}
    catch{RecordEvidenceFailure $Stage $_;return $false}
}
function TryWriteJson($Path,$Value,$Stage){
    try{WriteJson $Path $Value;return $true}
    catch{RecordEvidenceFailure $Stage $_;return $false}
}
function GetSha256Bytes($Bytes){
    $Hasher=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($Hasher.ComputeHash($Bytes))).Replace('-','').ToUpperInvariant()}finally{$Hasher.Dispose()}
}
function GetFileEvidence($Path){
    $FullPath=[IO.Path]::GetFullPath($Path)
    if(!(Test-Path -LiteralPath $FullPath -PathType Leaf)){
        return [ordered]@{Path=$FullPath;Exists=$false;Length=$null;LastWriteTimeUtc=$null;SHA256=$null}
    }
    $Item=Get-Item -LiteralPath $FullPath
    return [ordered]@{
        Path=$FullPath
        Exists=$true
        Length=$Item.Length
        LastWriteTimeUtc=$Item.LastWriteTimeUtc.ToUniversalTime().ToString('o')
        SHA256=(Get-FileHash -Algorithm SHA256 -LiteralPath $FullPath).Hash.ToUpperInvariant()
    }
}
function GetSourceManifest($Root){
    $RootFull=[IO.Path]::GetFullPath($Root)
    $Extensions=@('.c','.cc','.cpp','.cxx','.h','.hh','.hpp','.hxx','.inc','.inl','.ipp')
    $PathMap=@{}
    $RelativePaths=[Collections.Generic.List[string]]::new()
    Get-ChildItem -LiteralPath $RootFull -Recurse -File|Where-Object{$Extensions -contains $_.Extension.ToLowerInvariant()}|ForEach-Object{
        $Relative=[IO.Path]::GetRelativePath($RootFull,$_.FullName).Replace('\','/')
        $PathMap[$Relative]=$_.FullName
        [void]$RelativePaths.Add($Relative)
    }
    $RelativePaths.Sort([StringComparer]::Ordinal)
    $Entries=[Collections.Generic.List[object]]::new()
    foreach($Relative in $RelativePaths){
        $File=Get-Item -LiteralPath $PathMap[$Relative]
        $Hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $File.FullName).Hash.ToUpperInvariant()
        [void]$Entries.Add([ordered]@{Path=$Relative;Length=$File.Length;SHA256=$Hash})
    }
    $Lines=@($Entries.ToArray()|ForEach-Object{($_.SHA256+"`t"+$_.Path)})
    $Canonical=if($Lines.Count){[string]::Join("`n",$Lines)+"`n"}else{''}
    return [ordered]@{
        Root=$RootFull
        GeneratedUtc=[DateTime]::UtcNow.ToString('o')
        Algorithm='SHA256(file bytes); canonical UTF-8 LF lines SHA256<TAB>normalized relative path, ordinal path order; manifest hash is SHA256(canonical bytes)'
        FileCount=$Entries.Count
        Files=@($Entries.ToArray())
        ManifestSha256=GetSha256Bytes ($Utf8.GetBytes($Canonical))
    }
}
function GetOwnedEntry($Identity){
    if($null-eq$Identity){return $null}
    foreach($Entry in @($Owned)){
        if(TestProcessIdentity $Entry $Identity){return $Entry}
    }
    return $null
}

function AddOwnedEntry($Entry){
    if($null-eq$Entry -or $null-eq$Entry.Pid -or
       [string]::IsNullOrWhiteSpace([string]$Entry.Path) -or
       [string]::IsNullOrWhiteSpace([string]$Entry.PathSource) -or
       [string]::IsNullOrWhiteSpace([string]$Entry.StartTime) -or
       [string]::IsNullOrWhiteSpace([string]$Entry.CreationDate) -or
       [string]::IsNullOrWhiteSpace([string]$Entry.CreationDateSource)){
        RecordEvidenceFailure ('owner inventory add '+[string]$Entry.Name) 'incomplete process identity'
        return $false
    }
    foreach($Existing in @($Owned)){
        if($null-ne$Existing.Pid -and [int]$Existing.Pid -eq [int]$Entry.Pid){
            $SameIdentity=TestProcessIdentity $Existing $Entry
            $Reason=if($SameIdentity){'duplicate owner identity'}else{'duplicate PID with a different process identity'}
            RecordEvidenceFailure ('owner inventory add '+[string]$Entry.Name) ($Reason+' PID='+[string]$Entry.Pid)
            return $false
        }
    }
    try{[void]$Owned.Add($Entry);return $true}
    catch{RecordEvidenceFailure ('owner inventory add '+[string]$Entry.Name) $_;return $false}
}

function ConvertProcessEvidence($Entry,$Cleanup){
    return [ordered]@{
        Pid=$Entry.Pid
        Path=$Entry.Path
        PathSource=$Entry.PathSource
        Start=$Entry.Start
        StartTime=$Entry.StartTime
        CreationDate=$Entry.CreationDate
        CreationDateSource=$Entry.CreationDateSource
        IdentityEvidenceBoundary=$Entry.IdentityEvidenceBoundary
        Exit=$Entry.Exit
        ExitCode=$Entry.ExitCode
        ExitMethod=$Entry.ExitMethod
        Name=$Entry.Name
        Exited=$Entry.Exited
        RegistrationSucceeded=[bool]$Entry.RegistrationSucceeded
        Cleanup=$Cleanup
        OwnerRegistrationError=$Entry.OwnerRegistrationError
    }
}
function GetOwnedEntryForProcess($P){
    if($null-eq$P){return $null}
    foreach($Entry in @($Owned)){
        if($null-eq$Entry.Process -or ![object]::ReferenceEquals($Entry.Process,$P)){continue}
        try{
            if($P.HasExited){
                if(TestExitedProcessIdentity $P $Entry){return (GetOwnedEntry $Entry)}
                return $null
            }
            $Identity=GetProcessIdentity $P.Id $P $Entry.Path
            $Matched=GetOwnedEntry $Identity
            if($null-ne$Matched -and [object]::ReferenceEquals($Matched.Process,$P)){return $Matched}
        }catch{RecordEvidenceFailure ('owner lookup '+[string]$Entry.Name) $_}
        return $null
    }
    return $null
}
function RecordProcessExit($P,$Method){
    try{
        if($null-eq$P-or !$P.HasExited){return}
        $Entry=GetOwnedEntryForProcess $P
        if($null-eq$Entry){return}
        $Entry.Exited=$true
        try{$Entry.Exit=$P.ExitTime.ToUniversalTime().ToString('o')}catch{RecordEvidenceFailure 'process exit time' $_}
        try{$Entry.ExitCode=$P.ExitCode}catch{RecordEvidenceFailure 'process exit code' $_}
        try{if([string]::IsNullOrEmpty([string]$Entry.ExitMethod)){$Entry.ExitMethod=$Method}}catch{RecordEvidenceFailure 'process exit method' $_}
    }catch{RecordEvidenceFailure 'process exit recording' $_}
}
function StopProcessSafely($P,$Entry){
    $Result=[ordered]@{
        Attempted=$false
        Succeeded=$false
        Method=$null
        Pid=$null
        Path=$Entry.Path
        PathSource=$Entry.PathSource
        StartTime=$Entry.StartTime
        CreationDate=$Entry.CreationDate
        CreationDateSource=$Entry.CreationDateSource
        IdentityEvidenceBoundary=$Entry.IdentityEvidenceBoundary
        IdentityVerified=$false
        Name=$Entry.Name
        Error=$null
    }
    try{
        if($null-ne$Entry.Pid){$Result.Pid=[int]$Entry.Pid}
        if($null-eq$Result.Pid -and $null-ne$P){$Result.Pid=[int]$P.Id}
        if($null-eq$Result.Pid -or $Result.Pid -le 0){throw 'No confirmed PID for safe cleanup'}
        $Candidate=$P
        if($null-eq$Candidate){$Candidate=Get-Process -Id $Result.Pid -ErrorAction Stop}
        try{
            if($Candidate.HasExited){
                $CurrentIdentity=GetCurrentProcessIdentity $Result.Pid $Entry.Path
                if($null-eq$CurrentIdentity){
                    if(-not (TestExitedProcessIdentity $Candidate $Entry)){
                        throw ('Refusing cleanup for PID '+$Result.Pid+'; exited process identity does not match owner record')
                    }
                    $Result.IdentityVerified=$true
                    $Result.Succeeded=$true
                    $Result.Method='AlreadyExited'
                    return [PSCustomObject]$Result
                }
                if(-not (TestProcessIdentity $Entry $CurrentIdentity)){
                    throw ('Refusing cleanup for PID '+$Result.Pid+'; PID was reused by a different process identity')
                }
                $Candidate=Get-Process -Id $Result.Pid -ErrorAction Stop
            }
        }catch{RecordEvidenceFailure ('process state '+[string]$Entry.Name) $_}
        $Result.Attempted=$true
        $CandidateIdentity=GetProcessIdentity $Result.Pid $Candidate $Entry.Path
        if(-not (TestProcessIdentity $Entry $CandidateIdentity)){
            throw ('Refusing cleanup for PID '+$Result.Pid+'; complete process identity does not match owner record')
        }
        $Result.IdentityVerified=$true
        $Candidate.Kill()
        if(!$Candidate.WaitForExit(10000)){throw ('Process cleanup timeout for PID '+$Result.Pid)}
        if(!$Candidate.HasExited){throw ('Process remained alive after cleanup for PID '+$Result.Pid)}
        $Result.Succeeded=$true
        $Result.Method='Stop/Kill'
    }catch{
        $Result.Error=[string]$_
        RecordEvidenceFailure ('process cleanup '+[string]$Entry.Name) $_
    }
    return [PSCustomObject]$Result
}
function ReadLive($Path){
    $Stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    $Reader=[IO.StreamReader]::new($Stream)
    try{return $Reader.ReadToEnd()}finally{$Reader.Dispose()}
}
function FreePort {
    $L=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
    $L.Start();try{return $L.LocalEndpoint.Port}finally{$L.Stop()}
}
function FreeUdpPort {
    $U=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
    try{return $U.Client.LocalEndPoint.Port}finally{$U.Dispose()}
}
function Launch($Path,$Arguments,$Name){
    $FullPath=GetCanonicalPath $Path
    $Out=Join-Path $OutputDirectory ($Name+'.stdout.log');$Err=Join-Path $OutputDirectory ($Name+'.stderr.log')
    $P=$null
    $ProcessId=$null
    $Start=$null
    $CreationDate=$null
    $CreationDateSource=$null
    $PathSource='CanonicalLaunchArtifact'
    $Identity=$null
    $Entry=$null
    try{
        $P=Start-Process -FilePath $Path -ArgumentList $Arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput $Out -RedirectStandardError $Err -WorkingDirectory $RepoRoot
        try{$ProcessId=[int]$P.Id}catch{throw 'Start-Process returned no confirmed PID'}
        if($ProcessId -le 0){throw ('Start-Process returned invalid PID '+$ProcessId)}
        $Identity=GetProcessIdentity $ProcessId $P $FullPath
        if(![String]::Equals($Identity.Path,$FullPath,[StringComparison]::OrdinalIgnoreCase)){
            throw ('Start-Process PID '+$ProcessId+' executable path mismatch; expected='+$FullPath+' actual='+$Identity.Path)
        }
        $Start=$Identity.StartTime
        $CreationDate=$Identity.CreationDate
        $CreationDateSource=$Identity.CreationDateSource
        $PathSource=$Identity.PathSource
        $Entry=[PSCustomObject]@{
            Pid=$ProcessId
            Path=$FullPath
            PathSource=$PathSource
            Start=$Start
            StartTime=$Start
            CreationDate=$CreationDate
            CreationDateSource=$CreationDateSource
            IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary
            Exit=$null
            ExitCode=$null
            ExitMethod=$null
            Name=$Name
            Process=$P
            Exited=$false
            RegistrationSucceeded=$false
            OwnerRegistrationError=$null
            Cleanup=$null
        }
        if(-not (AddOwnedEntry $Entry)){throw ('Owner inventory add failed for '+$Name+' PID='+$ProcessId)}
        $Entry.RegistrationSucceeded=$true
        return $P
    }catch{
        $Original=$_
        if($null-eq$Entry){
            $Entry=[PSCustomObject]@{
                Pid=$ProcessId
                Path=$FullPath
                PathSource=$PathSource
                Start=$Start
                StartTime=$Start
                CreationDate=$CreationDate
                CreationDateSource=$CreationDateSource
                IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary
                Exit=$null
                ExitCode=$null
                ExitMethod=$null
                Name=$Name
                Process=$P
                Exited=$false
                RegistrationSucceeded=$false
                OwnerRegistrationError=[string]$Original
                Cleanup=$null
            }
        }else{
            $Entry.RegistrationSucceeded=$false
            $Entry.OwnerRegistrationError=[string]$Original
        }
        $Failure=[ordered]@{
            Pid=$ProcessId
            Path=$FullPath
            PathSource=$PathSource
            Start=$Start
            StartTime=$Start
            CreationDate=$CreationDate
            CreationDateSource=$CreationDateSource
            IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary
            Name=$Name
            RegistrationSucceeded=$false
            Error=[string]$Original
            Cleanup=$null
        }
        if($null-ne$P-or$null-ne$ProcessId){
            $Failure.Cleanup=StopProcessSafely $P $Entry
        }else{
            $Failure.Cleanup=[ordered]@{Attempted=$false;Succeeded=$false;Method='NoConfirmedProcess';Pid=$ProcessId;Path=$FullPath;PathSource=$PathSource;IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary;Name=$Name;Error='No confirmed process identity was returned'}
        }
        $Entry.Cleanup=$Failure.Cleanup
        [void](AddOwnedEntry $Entry)
        RecordEvidenceFailure ('launch owner registration '+$Name) $Original
        try{[void]$LaunchFailures.Add($Failure)}catch{RecordEvidenceFailure 'launch failure evidence' $_}
        throw $Original
    }
}
function WaitReady($P,$Path,$Pattern){
    $Until=[DateTime]::UtcNow.AddSeconds(15)
    while([DateTime]::UtcNow-lt $Until){
        if($P.HasExited){RecordProcessExit $P 'ExitedBeforeReady';throw ('Process exited before ready: '+$P.ExitCode+' '+$Path)}
        $T=if(Test-Path $Path){ReadLive $Path}else{''}
        $M=[regex]::Match($T,$Pattern);if($M.Success){return $M}
        Start-Sleep -Milliseconds 50
    }
    throw ('Ready timeout '+$Path)
}
function Client($Path,$Arguments,$Name,$Expected){
    $P=Launch $Path $Arguments $Name
    if(!$P.WaitForExit(15000)){StopOwned $P;throw ('Client timed out '+$Name)}
    RecordProcessExit $P 'NaturalProcessExit'
    $Text=[IO.File]::ReadAllText((Join-Path $OutputDirectory ($Name+'.stdout.log')))
    $Cases.Add([PSCustomObject]@{Name=$Name;Arguments=$Arguments;Pid=$P.Id;ExitCode=$P.ExitCode;Expected=$Expected;Payload=$Text.Trim();Passed=($P.ExitCode-eq $Expected)})
    if($P.ExitCode-ne $Expected){throw ('Client exit mismatch '+$Name+' actual='+$P.ExitCode+' expected='+$Expected)}
    return $Text
}
function AssertCaseContract {
    if($ExpectedCaseNames.Count -ne 18){throw ('Expected case contract must contain 18 names; actual='+$ExpectedCaseNames.Count)}
    if($Cases.Count -ne 18){throw ('Provider18 case count mismatch; actual='+$Cases.Count+' expected=18')}
    for($Index=0;$Index-lt $ExpectedCaseNames.Count;$Index++){
        if([string]$Cases[$Index].Name -ne [string]$ExpectedCaseNames[$Index]){
            throw ('Provider18 case name mismatch at index '+$Index+'; actual='+$Cases[$Index].Name+' expected='+$ExpectedCaseNames[$Index])
        }
    }
    foreach($Case in $Cases){
        if(!$Case.Passed){throw ('Provider18 case did not pass: '+$Case.Name)}
        $Properties=@($Case.PSObject.Properties.Name)
        $HasInput=($Properties -contains 'Arguments') -or ($Properties -contains 'Payload') -or ($Properties -contains 'InputContract')
        if(!$HasInput){throw ('Provider18 case has no preserved input contract: '+$Case.Name)}
    }
}
function Config($Kind,$Name){
    $Value=Get-Content -Raw (Join-Path $RepoRoot 'Prism/Application/Configuration/PrismConfiguration.json')|ConvertFrom-Json -AsHashtable
    $Value.Runtime.WorkerCount=2
    $Value.Listeners.Tcp[0].Port=FreePort
    $Value.Listeners.Udp[0].Port=FreeUdpPort
    $Value.Listeners.Quic=@()
    $Value.Operations.Enabled=$false
    $Value.Logging.Level='Trace';$Value.Logging.Console=$false
    $Value.Logging.Directory=Join-Path $RunDirectory ($Name+'-logs');$Value.Logging.FileName='prism.log'
    $Value.Protocols=@(@{Id=$Name;Name=$Kind;Builtin=$Kind;Requires=@()})
    $Value.ProtocolBindings=@(@{Id=($Name+'-binding');ProtocolId=$Name;TcpEnabled=$true;UdpEnabled=$true;MuxModes=@();Priority=0;Recognition=@{}})
    if($Kind-eq 'socks5'){
        $Value.Accounts=@(@{Id='socks-account';SecretRef='';Credential='prepared-socks-password';Credentials=@{}})
    }else{
        $Value.Accounts=@(@{Id='ss-account-one';SecretRef='';Credential='5n5ESu953i/pjIp02oZvHA==';Credentials=@{}},@{Id='ss-account-two';SecretRef='';Credential='d3d3d3d3d3d3d3d3d3d3dw==';Credentials=@{}})
    }
    $Path=Join-Path $RunDirectory ($Name+'.json');WriteJson $Path $Value
    $CopyPath=Join-Path $OutputDirectory ($Name+'-configuration.json')
    Copy-Item -LiteralPath $Path -Destination $CopyPath
    $DynamicEvidence=GetFileEvidence $Path
    $CopyEvidence=GetFileEvidence $CopyPath
    $Record=[ordered]@{
        Name=$Name
        Kind=$Kind
        Path=[IO.Path]::GetFullPath($Path)
        SHA256=$DynamicEvidence.SHA256
        Length=$DynamicEvidence.Length
        LastWriteTimeUtc=$DynamicEvidence.LastWriteTimeUtc
        CopyPath=$CopyEvidence.Path
        CopySHA256=$CopyEvidence.SHA256
        OperationsEnabled=[bool]$Value.Operations.Enabled
        OperationsState=if($Value.Operations.Enabled){'enabled'}else{'disabled'}
    }
    [void]$DynamicConfigurations.Add($Record)
    WriteJson (Join-Path $OutputDirectory 'dynamic-configs.json') @($DynamicConfigurations.ToArray())
    return [ordered]@{Path=$Path;Tcp=$Value.Listeners.Tcp[0].Port;Udp=$Value.Listeners.Udp[0].Port;ConfigHash=$DynamicEvidence.SHA256;OperationsEnabled=[bool]$Value.Operations.Enabled}
}
function StopOwned($P){
    if($null-eq$P){throw 'Cannot clean up a null process'}
    $Entry=GetOwnedEntryForProcess $P
    if($null-eq$Entry){throw ('No owner record for PID '+$P.Id)}
    $Result=StopProcessSafely $P $Entry
    if(!$Result.Succeeded){throw ('Safe cleanup failed for '+$Entry.Name+' PID='+$Entry.Pid+' path='+$Entry.Path+' error='+$Result.Error)}
    RecordProcessExit $P $Result.Method
}
function StatsCount($Ports){
    $Response=Invoke-WebRequest ('http://127.0.0.1:'+$Ports.control+'/stats')
    return @($Response.Content|ConvertFrom-Json).Count
}
function GetDynamicConfigurationValue($Configuration,$Key){
    if($null-eq$Configuration){throw 'Dynamic configuration record is missing'}
    if($Configuration -isnot [System.Collections.IDictionary]){
        throw ('Dynamic configuration record has unsupported type: '+$Configuration.GetType().FullName)
    }
    $Record=[System.Collections.IDictionary]$Configuration
    if(-not $Record.Contains($Key)){throw ('Dynamic configuration record is missing key: '+$Key)}
    return $Record[$Key]
}
try{
    $Prism=Join-Path $RepoRoot 'build/src/Prism.exe'
    $PrismMain=Join-Path $RepoRoot 'Prism/Application/Main/PrismMain.hpp'
    $Startup=Join-Path $RepoRoot 'Prism/Application/Startup/Start.hpp'
    $ConfigTemplate=Join-Path $RepoRoot 'Prism/Application/Configuration/PrismConfiguration.json'
    $RunnerPath=[IO.Path]::GetFullPath($PSCommandPath)
    $RunnerEvidence=GetFileEvidence $RunnerPath
    $MainEvidence=GetFileEvidence $PrismMain
    $StartupEvidence=GetFileEvidence $Startup
    $ConfigTemplateEvidence=GetFileEvidence $ConfigTemplate
    $PrismEvidence=GetFileEvidence $Prism
    $SourceManifest=GetSourceManifest (Join-Path $RepoRoot 'Prism')
    WriteJson $SourceManifestPath $SourceManifest
    $EpochLines=@(
        'Provider18EvidenceEpoch/v1'
        ('SourceManifestSha256='+$SourceManifest.ManifestSha256)
        ('RunnerSha256='+$RunnerEvidence.SHA256)
        ('PrismMainSha256='+$MainEvidence.SHA256)
        ('StartSha256='+$StartupEvidence.SHA256)
        ('ConfigTemplateSha256='+$ConfigTemplateEvidence.SHA256)
        ('PrismSha256='+$PrismEvidence.SHA256)
    )
    $EpochMarker=GetSha256Bytes ($Utf8.GetBytes(([string]::Join("`n",$EpochLines)+"`n")))
    $StaticEvidence=[ordered]@{
        Schema='Provider18Evidence/v2'
        CapturedUtc=$EvidenceTimeUtc
        EpochMarker=$EpochMarker
        EpochAlgorithm='SHA256(UTF-8 LF canonical lines in the recorded order: source manifest, runner, PrismMain, Start, config template, Prism)'
        SourceBinaryProvenance=[ordered]@{
            Status='missing'
            Boundary='Source manifest and Prism SHA256 are recorded independently; no source-to-binary build mapping is asserted.'
        }
        SourceManifestPath=[IO.Path]::GetFullPath($SourceManifestPath)
        SourceManifestSha256=$SourceManifest.ManifestSha256
        SourceManifestAlgorithm=$SourceManifest.Algorithm
        Runner=$RunnerEvidence
        PrismMain=$MainEvidence
        Start=$StartupEvidence
        ConfigTemplate=$ConfigTemplateEvidence
        Prism=$PrismEvidence
    }
    $Echo=Launch (Get-Command node).Source @((Join-Path $RepoRoot 'tests/Prism/Integration/ProviderEcho.mjs')) 'echo'
    $Ready=WaitReady $Echo (Join-Path $OutputDirectory 'echo.stdout.log') '(?m)^\{.*\}$'
    $EchoPorts=$Ready.Value|ConvertFrom-Json
    $Socks=Join-Path $RepoRoot 'build/tests/Prism/Integration/InteropSocks5.exe'
    $Ss=Join-Path $RepoRoot 'build/tests/Prism/Integration/InteropSs2022Client.exe'
    $Raw=Join-Path $RepoRoot 'build/tests/Prism/Integration/InteropProviderDatagrams.exe'
    $SocksConfig=Config 'socks5' 'socks-real'
    $Server=Launch $Prism @($SocksConfig.Path) 'socks-server'
    $null=WaitReady $Server (Join-Path $OutputDirectory 'socks-server.stdout.log') 'Prism READY.*'
    for($Round=1;$Round-le 3;$Round++){
        $null=Client $Socks @('-mode','client','-addr',('127.0.0.1:'+$SocksConfig.Tcp),'-target',('127.0.0.1:'+$EchoPorts.tcp),'-username','user','-password','prepared-socks-password') ('socks-tcp-'+$Round) 0
    }
    $Before=StatsCount $EchoPorts
    $null=Client $Socks @('-mode','client','-addr',('127.0.0.1:'+$SocksConfig.Tcp),'-target',('127.0.0.1:'+$EchoPorts.tcp),'-username','user','-password','wrong-password') 'socks-bad-auth' 1
    $After=StatsCount $EchoPorts
    if($After-ne $Before){throw 'Bad SOCKS authentication reached upstream'}
    $Refused=FreePort
    $null=Client $Socks @('-mode','client','-addr',('127.0.0.1:'+$SocksConfig.Tcp),'-target',('127.0.0.1:'+$Refused),'-username','user','-password','prepared-socks-password') 'socks-postdial-refused' 1
    $Text=Client $Raw @('socksudp',$SocksConfig.Tcp,$EchoPorts.udp,'prepared-socks-password') 'socks-udp-control' 0
    $Bound=[int][regex]::Match($Text,'BND_PORT=(\d+)').Groups[1].Value
    $Remaining=@(Get-NetUDPEndpoint -LocalPort $Bound -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $Server.Id)
    if($Remaining.Count){throw 'SOCKS BND socket remained after control EOF'}
    $Cases.Add([PSCustomObject]@{
        Name='socks-bnd-socket-closed'
        Arguments=@('socksudp',$SocksConfig.Tcp,$EchoPorts.udp,'prepared-socks-password')
        Payload=$Text.Trim()
        InputContract='SOCKS UDP control must return BND_PORT and close its BND socket after control EOF.'
        Port=$Bound
        ServerPid=$Server.Id
        Remaining=$Remaining.Count
        Passed=$true
    })
    if($Server.HasExited){RecordProcessExit $Server 'UnexpectedExit';throw 'SOCKS server crashed'}
    StopOwned $Server
    $SsConfig=Config 'ss2022' 'ss-real'
    $Server=Launch $Prism @($SsConfig.Path) 'ss-server'
    $null=WaitReady $Server (Join-Path $OutputDirectory 'ss-server.stdout.log') 'Prism READY.*'
    $Keys=@('5n5ESu953i/pjIp02oZvHA==','d3d3d3d3d3d3d3d3d3d3dw==')
    for($Index=0;$Index-lt $Keys.Count;$Index++){
        for($Round=1;$Round-le 3;$Round++){
            $null=Client $Ss @(('127.0.0.1:'+$SsConfig.Tcp),('127.0.0.1:'+$EchoPorts.tcp),$Keys[$Index]) ('ss-tcp-account-'+($Index+1)+'-'+$Round) 0
        }
        $Before=StatsCount $EchoPorts
        $null=Client $Raw @('ssudp',$SsConfig.Udp,$EchoPorts.udp,$Keys[$Index]) ('ss-udp-account-'+($Index+1)) 0
        $After=StatsCount $EchoPorts
        if($After-ne ($Before+1)){throw 'SS replay reached real upstream or expected packet missing'}
    }
    $Before=StatsCount $EchoPorts
    $BadTcpText=Client $Ss @(('127.0.0.1:'+$SsConfig.Tcp),('127.0.0.1:'+$EchoPorts.tcp),'AAAAAAAAAAAAAAAAAAAAAA==') 'ss-tcp-bad-key' 1
    $BadUdpText=Client $Raw @('ssbad',$SsConfig.Udp,$EchoPorts.udp,'AAAAAAAAAAAAAAAAAAAAAA==') 'ss-udp-bad-key' 0
    $After=StatsCount $EchoPorts
    if($After-ne $Before){throw 'SS bad key reached real upstream'}
    $Cases.Add([PSCustomObject]@{
        Name='negative-no-egress'
        Arguments=[ordered]@{
            Tcp=@('127.0.0.1:'+$SsConfig.Tcp,'127.0.0.1:'+$EchoPorts.tcp,'AAAAAAAAAAAAAAAAAAAAAA==')
            Udp=@('ssbad',$SsConfig.Udp,$EchoPorts.udp,'AAAAAAAAAAAAAAAAAAAAAA==')
        }
        Payload=[ordered]@{Tcp=$BadTcpText.Trim();Udp=$BadUdpText.Trim()}
        InputContract='Invalid SS2022 TCP and UDP credentials must be rejected without increasing upstream stats.'
        Before=$Before
        After=$After
        Passed=$true
    })
    if($Server.HasExited){RecordProcessExit $Server 'UnexpectedExit';throw 'SS server crashed'}
    StopOwned $Server
    WriteJson (Join-Path $OutputDirectory 'echo-records.json') @(Invoke-RestMethod ('http://127.0.0.1:'+$EchoPorts.control+'/stop'))
    $Echo.WaitForExit(3000)|Out-Null
    RecordProcessExit $Echo 'ControlStop'
    AssertCaseContract
    $MainCompleted=$true
}catch{
    $MainFailure=$_
    $FailureText=[string]$_
}finally{
    try{
    if($null-ne$MainFailure){
        [void](TryWriteText (Join-Path $OutputDirectory 'failure.txt') $FailureText 'failure evidence')
    }
    foreach($Entry in @($Owned)){
        try{
            if(!$Entry.RegistrationSucceeded -and $null-ne$Entry.Cleanup -and $Entry.Cleanup.Succeeded){continue}
            $StopResult=StopProcessSafely $Entry.Process $Entry
            $Entry.Cleanup=$StopResult
            if(!$StopResult.Succeeded){
                $CleanupHealthy=$false
            }else{
                if($null-ne$Entry.Process){
                    RecordProcessExit $Entry.Process $StopResult.Method
                    try{$Entry.Exited=$Entry.Process.HasExited}catch{RecordEvidenceFailure 'owner exit state' $_;$CleanupHealthy=$false}
                }else{$Entry.Exited=$true}
            }
        }catch{
            $CleanupHealthy=$false
            RecordEvidenceFailure ('owner cleanup '+[string]$Entry.Name) $_
        }
    }
    try{
        $ConfirmedIdentities=[Collections.Generic.List[object]]::new()
        $ConfirmedPidSet=[Collections.Generic.HashSet[int]]::new()
        $SeenIdentityKeys=[Collections.Generic.HashSet[string]]::new()
        foreach($Entry in @($Owned)){
            if($null-eq$Entry.Pid){continue}
            $Identity=[PSCustomObject]@{
                Pid=[int]$Entry.Pid
                Path=$Entry.Path
                PathSource=$Entry.PathSource
                Start=$Entry.Start
                StartTime=$Entry.StartTime
                CreationDate=$Entry.CreationDate
                CreationDateSource=$Entry.CreationDateSource
                IdentityEvidenceBoundary=$Entry.IdentityEvidenceBoundary
            }
            $IdentityKey=GetProcessIdentityKey $Identity
            if($SeenIdentityKeys.Add($IdentityKey)){
                [void]$ConfirmedPidSet.Add([int]$Entry.Pid)
                [void]$ConfirmedIdentities.Add($Identity)
            }
        }
        foreach($Failure in @($LaunchFailures)){
            if($null-eq$Failure.Pid){continue}
            $Identity=[PSCustomObject]@{
                Pid=[int]$Failure.Pid
                Path=$Failure.Path
                PathSource=$Failure.PathSource
                Start=$Failure.Start
                StartTime=$Failure.StartTime
                CreationDate=$Failure.CreationDate
                CreationDateSource=$Failure.CreationDateSource
                IdentityEvidenceBoundary=$Failure.IdentityEvidenceBoundary
            }
            if(-not (TestCompleteProcessIdentity $Identity)){
                RecordEvidenceFailure 'confirmed PID assembly' ('Skipping incomplete failed owner identity PID='+[string]$Failure.Pid)
                continue
            }
            $IdentityKey=GetProcessIdentityKey $Identity
            if($SeenIdentityKeys.Add($IdentityKey)){
                [void]$ConfirmedPidSet.Add([int]$Failure.Pid)
                [void]$ConfirmedIdentities.Add($Identity)
            }
        }
        $UnverifiedProcessPids=@($LaunchFailures|Where-Object{$null-ne$_.Pid -and -not (TestCompleteProcessIdentity $_)}|ForEach-Object{[int]$_.Pid}|Sort-Object -Unique)
        $ConfirmedPids=@($ConfirmedPidSet|Sort-Object)
        $ConfirmedIdentities=@($ConfirmedIdentities.ToArray())
    }catch{
        $ConfirmedPids=$null
        $ConfirmedIdentities=$null
        $CleanupHealthy=$false
        RecordEvidenceFailure 'confirmed PID assembly' $_
    }
    try{
        $OwnedRecords=[Collections.Generic.List[object]]::new()
        $SeenIdentityKeys=[Collections.Generic.HashSet[string]]::new()
        foreach($Entry in @($Owned)){
            if($null-ne$Entry.Pid -and (TestCompleteProcessIdentity $Entry)){
                [void]$SeenIdentityKeys.Add((GetProcessIdentityKey $Entry))
            }
            [void]$OwnedRecords.Add((ConvertProcessEvidence $Entry $Entry.Cleanup))
        }
        foreach($Failure in @($LaunchFailures)){
            $FailurePid=$Failure.Pid
            if($null-ne$FailurePid -and (TestCompleteProcessIdentity $Failure)){
                $FailureKey=GetProcessIdentityKey $Failure
                if($SeenIdentityKeys.Contains($FailureKey)){continue}
                [void]$SeenIdentityKeys.Add($FailureKey)
            }
            [void]$OwnedRecords.Add([ordered]@{
                Pid=$Failure.Pid
                Path=$Failure.Path
                PathSource=$Failure.PathSource
                Start=$Failure.Start
                StartTime=$Failure.StartTime
                CreationDate=$Failure.CreationDate
                CreationDateSource=$Failure.CreationDateSource
                IdentityEvidenceBoundary=$Failure.IdentityEvidenceBoundary
                Exit=$null
                ExitCode=$null
                ExitMethod=$null
                Name=$Failure.Name
                Exited=$false
                RegistrationSucceeded=$false
                Cleanup=$Failure.Cleanup
                OwnerRegistrationError=$Failure.Error
            })
        }
        $OwnedRecords=@($OwnedRecords.ToArray())
    }catch{
        $OwnedRecords=[ordered]@{
            Status='unavailable'
            Error=[string]$_
            ConfirmedPids=@($ConfirmedPids)
            RegistrationFailures=@($LaunchFailures.ToArray())
        }
        $CleanupHealthy=$false
        RecordEvidenceFailure 'owned process record assembly' $_
    }
    if(-not (TryWriteJson (Join-Path $OutputDirectory 'cases.json') @($Cases.ToArray()) 'cases evidence')){$CleanupHealthy=$false}
    if(-not (TryWriteJson (Join-Path $OutputDirectory 'owned-processes.json') $OwnedRecords 'owned process evidence')){$CleanupHealthy=$false}
    try{
        if($null-eq$ConfirmedPids -or $null-eq$ConfirmedIdentities){throw 'Confirmed process identity inventory is unavailable'}
        if($UnverifiedProcessPids.Count -ne 0){throw ('Process inventory cannot prove cleanup for unverified launch PID(s): '+[string]::Join(',',@($UnverifiedProcessPids)))}
        $FreshRecords=[Collections.Generic.List[object]]::new()
        $Mismatches=[Collections.Generic.List[object]]::new()
        foreach($ExpectedIdentity in @($ConfirmedIdentities)){
            $ObservedIdentity=GetCurrentProcessIdentity $ExpectedIdentity.Pid $ExpectedIdentity.Path
            if($null-eq$ObservedIdentity){continue}
            $IdentityMatch=TestProcessIdentity $ExpectedIdentity $ObservedIdentity
            $Record=[ordered]@{
                Pid=$ObservedIdentity.Pid
                ExpectedPath=$ExpectedIdentity.Path
                ExpectedPathSource=$ExpectedIdentity.PathSource
                ExpectedStart=$ExpectedIdentity.Start
                ExpectedStartTime=$ExpectedIdentity.StartTime
                ExpectedCreationDate=$ExpectedIdentity.CreationDate
                ExpectedCreationDateSource=$ExpectedIdentity.CreationDateSource
                ObservedPath=$ObservedIdentity.Path
                ObservedPathSource=$ObservedIdentity.PathSource
                ObservedStart=$ObservedIdentity.Start
                ObservedStartTime=$ObservedIdentity.StartTime
                ObservedCreationDate=$ObservedIdentity.CreationDate
                ObservedCreationDateSource=$ObservedIdentity.CreationDateSource
                IdentityEvidenceBoundary=$ObservedIdentity.IdentityEvidenceBoundary
                IdentityMatch=[bool]$IdentityMatch
            }
            [void]$FreshRecords.Add($Record)
            if(!$IdentityMatch){[void]$Mismatches.Add($Record)}
        }
        $Fresh=@($FreshRecords.ToArray())
        $InventoryIdentityMismatches=@($Mismatches.ToArray())
        $RemainingCount=$Fresh.Count
        $ProcessInventoryCaptured=$true
        if($InventoryIdentityMismatches.Count -ne 0){
            $CleanupHealthy=$false
            RecordEvidenceFailure 'remaining process identity mismatch' ('Count='+$InventoryIdentityMismatches.Count)
        }
    }catch{
        $Fresh=$null
        $InventoryIdentityMismatches=@()
        $RemainingCount=-1
        $ProcessInventoryError=[string]$_
        $CleanupHealthy=$false
        RecordEvidenceFailure 'remaining process inventory' $_
    }
    try{
        AssertOwnedRunDirectory $RunDirectory $RunMarkerToken $RunMarkerPath
        Get-ChildItem -LiteralPath $RunDirectory -Recurse -File -Filter '*.log'|ForEach-Object{
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $OutputDirectory ($_.Directory.Name+'-'+$_.Name))|Out-Null
        }
    }catch{
        $CleanupHealthy=$false
        RecordEvidenceFailure 'log capture' $_
    }
    try{
        AssertOwnedRunDirectory $RunDirectory $RunMarkerToken $RunMarkerPath
        Remove-Item -LiteralPath $RunDirectory -Recurse -Force -ErrorAction Stop
    }catch{
        $LiveDirectoryCleanupFailed=$true
        $CleanupHealthy=$false
        RecordEvidenceFailure 'run directory deletion' $_
    }
    try{
        if(Test-Path -LiteralPath $RunDirectory){
            $null=GetDirectoryInfoSafe $RunDirectory $false
            $LiveDirectoryRemaining=$true
        }else{$LiveDirectoryRemaining=$false}
    }catch{$LiveDirectoryRemaining=$true;$CleanupHealthy=$false;RecordEvidenceFailure 'run directory residue check' $_}
    if(!$ProcessInventoryCaptured){$CleanupHealthy=$false}
    if($ProcessInventoryCaptured -and $RemainingCount -ne 0){$CleanupHealthy=$false;RecordEvidenceFailure 'remaining owned processes' ('RemainingCount='+$RemainingCount)}
    if($LiveDirectoryRemaining){$CleanupHealthy=$false;RecordEvidenceFailure 'live directory residue' 'LiveDirectoryRemaining=true'}
    if($LiveDirectoryCleanupFailed){$CleanupHealthy=$false}
    try{AssertCaseContract;$CaseContractPassed=$true}catch{$CaseContractPassed=$false;$CleanupHealthy=$false;RecordEvidenceFailure 'case contract' $_}
    try{$FinalEvidenceTimeUtc=[DateTime]::UtcNow.ToString('o')}catch{$FinalEvidenceTimeUtc=$EvidenceTimeUtc;$CleanupHealthy=$false;RecordEvidenceFailure 'final evidence time' $_}
    try{
        $BindingLines=[Collections.Generic.List[string]]::new()
        [void]$BindingLines.Add('Provider18EvidenceBinding/v1')
        [void]$BindingLines.Add('EpochMarker='+[string]$EpochMarker)
        [void]$BindingLines.Add('SourceBinaryProvenance=missing')
        foreach($Configuration in @($DynamicConfigurations.ToArray()|Sort-Object -Property @{Expression={[string](GetDynamicConfigurationValue $_ 'Name')}})){
            $ConfigurationName=[string](GetDynamicConfigurationValue $Configuration 'Name')
            $ConfigurationHash=[string](GetDynamicConfigurationValue $Configuration 'SHA256')
            if([string]::IsNullOrWhiteSpace($ConfigurationName) -or [string]::IsNullOrWhiteSpace($ConfigurationHash)){
                throw 'Dynamic configuration binding record has incomplete name/hash evidence'
            }
            [void]$BindingLines.Add('DynamicConfig['+$ConfigurationName+']Sha256='+$ConfigurationHash)
        }
        [void]$BindingLines.Add('NaturalMainExitClaim=false')
        $CanonicalBinding=[string]::Join([string][char]10,$BindingLines.ToArray())+[string][char]10
        $EvidenceBindingMarker=GetSha256Bytes ($Utf8.GetBytes($CanonicalBinding))
    }catch{$EvidenceBindingMarker=$null;$CleanupHealthy=$false;RecordEvidenceFailure 'evidence binding marker' $_}
    try{
        $EnabledNames=[Collections.Generic.List[string]]::new()
        $DisabledNames=[Collections.Generic.List[string]]::new()
        $ConfigurationEvidence=[Collections.Generic.List[object]]::new()
        foreach($Configuration in @($DynamicConfigurations.ToArray())){
            $ConfigurationName=[string](GetDynamicConfigurationValue $Configuration 'Name')
            $OperationsEnabled=[bool](GetDynamicConfigurationValue $Configuration 'OperationsEnabled')
            $OperationsState=[string](GetDynamicConfigurationValue $Configuration 'OperationsState')
            $ConfigurationHash=[string](GetDynamicConfigurationValue $Configuration 'SHA256')
            if([string]::IsNullOrWhiteSpace($ConfigurationName) -or [string]::IsNullOrWhiteSpace($ConfigurationHash)){
                throw 'Dynamic configuration operations record has incomplete name/hash evidence'
            }
            if($OperationsEnabled){[void]$EnabledNames.Add($ConfigurationName)}else{[void]$DisabledNames.Add($ConfigurationName)}
            [void]$ConfigurationEvidence.Add([ordered]@{
                Name=$ConfigurationName
                Enabled=$OperationsEnabled
                State=$OperationsState
                SHA256=$ConfigurationHash
            })
        }
        $EnabledConfigurations=@($EnabledNames.ToArray())
        $DisabledConfigurations=@($DisabledNames.ToArray())
        $OperationsSummary=[ordered]@{
            Expected='disabled'
            Enabled=@($EnabledConfigurations)
            Disabled=@($DisabledConfigurations)
            AllDisabled=($EnabledConfigurations.Count -eq 0 -and $ConfigurationEvidence.Count -gt 0)
            Configurations=@($ConfigurationEvidence.ToArray())
        }
    }catch{$CleanupHealthy=$false;RecordEvidenceFailure 'operations evidence' $_}
    try{
        $CleanupEvidence=[ordered]@{
            GeneratedUtc=$FinalEvidenceTimeUtc
            EvidenceTimeUtc=$FinalEvidenceTimeUtc
            NaturalMainExitClaim=$false
            IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary
            OutputDirectory=$OutputDirectoryCanonical
            RunDirectory=$RunDirectory
            ConfirmedPids=$ConfirmedPids
            ConfirmedIdentities=$ConfirmedIdentities
            UnverifiedProcessPids=$UnverifiedProcessPids
            OwnedPids=$ConfirmedPids
            OwnedProcessIdentities=$ConfirmedIdentities
            OwnerRegistrationFailures=@($LaunchFailures.ToArray())
            ProcessInventoryCaptured=$ProcessInventoryCaptured
            ProcessInventoryError=$ProcessInventoryError
            RemainingCount=$RemainingCount
            Remaining=$Fresh
            InventoryIdentityMismatches=$InventoryIdentityMismatches
            CaseContractPassed=$CaseContractPassed
            ExpectedCaseNames=$ExpectedCaseNames
            LiveDirectoryRemaining=$LiveDirectoryRemaining
            LiveDirectoryCleanupFailed=$LiveDirectoryCleanupFailed
            EvidenceFailures=@($EvidenceFailures.ToArray())
        }
    }catch{
        $CleanupHealthy=$false
        RecordEvidenceFailure 'cleanup inventory assembly' $_
        $CleanupEvidence=[ordered]@{
            GeneratedUtc=$FinalEvidenceTimeUtc
            EvidenceTimeUtc=$FinalEvidenceTimeUtc
            NaturalMainExitClaim=$false
            IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary
            OutputDirectory=$OutputDirectoryCanonical
            RunDirectory=$RunDirectory
            ConfirmedPids=$ConfirmedPids
            ConfirmedIdentities=$ConfirmedIdentities
            UnverifiedProcessPids=$UnverifiedProcessPids
            OwnedPids=$ConfirmedPids
            OwnedProcessIdentities=$ConfirmedIdentities
            OwnerRegistrationFailures=@($LaunchFailures.ToArray())
            ProcessInventoryCaptured=$false
            ProcessInventoryError=$ProcessInventoryError
            RemainingCount=-1
            Remaining=$null
            InventoryIdentityMismatches=$InventoryIdentityMismatches
            CaseContractPassed=$false
            ExpectedCaseNames=$ExpectedCaseNames
            LiveDirectoryRemaining=$true
            LiveDirectoryCleanupFailed=$true
            EvidenceFailures=@($EvidenceFailures.ToArray())
        }
    }
    if(-not (TryWriteJson (Join-Path $OutputDirectory 'cleanup-inventory.json') $CleanupEvidence 'cleanup inventory evidence')){$CleanupHealthy=$false}
    if($null-ne$SourceManifest){if(-not (TryWriteJson $SourceManifestPath $SourceManifest 'source manifest evidence')){$CleanupHealthy=$false}}
    $Status=if($MainCompleted -and $CleanupHealthy -and $CaseContractPassed -and $Cases.Count -eq 18 -and $ProcessInventoryCaptured -and $RemainingCount -eq 0 -and !$LiveDirectoryRemaining -and !$LiveDirectoryCleanupFailed -and $EvidenceFailures.Count -eq 0){'PASS'}else{'FAIL'}
    if($Status-ne 'PASS' -and $null-eq$MainFailure){
        $FailureText='Provider18 cleanup or evidence finalization failed; inspect cleanup-inventory.json and provenance.json.'
        [void](TryWriteText (Join-Path $OutputDirectory 'failure.txt') $FailureText 'cleanup failure evidence')
    }
    try{
        $Provenance=[ordered]@{
            Schema='Provider18Evidence/v2'
            Status=$Status
            EvidenceTimeUtc=$FinalEvidenceTimeUtc
            NaturalMainExitClaim=$false
            IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary
            EpochMarker=$EpochMarker
            EvidenceBindingMarker=$EvidenceBindingMarker
            SourceBinaryProvenance=if($null-ne$StaticEvidence){$StaticEvidence.SourceBinaryProvenance}else{[ordered]@{Status='missing';Boundary='Source manifest and Prism SHA256 are recorded independently; no source-to-binary build mapping is asserted.'}}
            Artifacts=$StaticEvidence
            SourceManifestPath=[IO.Path]::GetFullPath($SourceManifestPath)
            SourceManifestSha256=if($null-ne$SourceManifest){$SourceManifest.ManifestSha256}else{$null}
            SourceManifestAlgorithm=if($null-ne$SourceManifest){$SourceManifest.Algorithm}else{$null}
            RunnerSha256=if($null-ne$StaticEvidence){$StaticEvidence.Runner.SHA256}else{$null}
            PrismMainSha256=if($null-ne$StaticEvidence){$StaticEvidence.PrismMain.SHA256}else{$null}
            StartSha256=if($null-ne$StaticEvidence){$StaticEvidence.Start.SHA256}else{$null}
            ConfigTemplateSha256=if($null-ne$StaticEvidence){$StaticEvidence.ConfigTemplate.SHA256}else{$null}
            PrismSha256=if($null-ne$StaticEvidence){$StaticEvidence.Prism.SHA256}else{$null}
            PrismMtimeUtc=if($null-ne$StaticEvidence){$StaticEvidence.Prism.LastWriteTimeUtc}else{$null}
            DynamicConfigurations=@($DynamicConfigurations.ToArray())
            Operations=$OperationsSummary
            CaseCount=$Cases.Count
            ExpectedCaseNames=$ExpectedCaseNames
            CaseContractPassed=$CaseContractPassed
            MainCompleted=$MainCompleted
            MainFailure=$FailureText
            OwnerRegistrationFailures=@($LaunchFailures.ToArray())
            EvidenceFailures=@($EvidenceFailures.ToArray())
            OwnedProcesses=$OwnedRecords
            UnverifiedProcessPids=$UnverifiedProcessPids
            RemainingCount=$RemainingCount
            Remaining=$Fresh
            Cleanup=$CleanupEvidence
        }
    }catch{
        $CleanupHealthy=$false
        $Status='FAIL'
        RecordEvidenceFailure 'provenance assembly' $_
        $Provenance=[ordered]@{
            Schema='Provider18Evidence/v2'
            Status='FAIL'
            EvidenceTimeUtc=$FinalEvidenceTimeUtc
            NaturalMainExitClaim=$false
            IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary
            EpochMarker=$EpochMarker
            SourceBinaryProvenance=[ordered]@{Status='missing';Boundary='Source manifest and Prism SHA256 are recorded independently; no source-to-binary build mapping is asserted.'}
            Artifacts=$StaticEvidence
            SourceManifestPath=if($null-ne$SourceManifestPath){[IO.Path]::GetFullPath($SourceManifestPath)}else{$null}
            SourceManifestSha256=if($null-ne$SourceManifest){$SourceManifest.ManifestSha256}else{$null}
            SourceManifestAlgorithm=if($null-ne$SourceManifest){$SourceManifest.Algorithm}else{$null}
            RunnerSha256=if($null-ne$StaticEvidence){$StaticEvidence.Runner.SHA256}else{$null}
            PrismMainSha256=if($null-ne$StaticEvidence){$StaticEvidence.PrismMain.SHA256}else{$null}
            StartSha256=if($null-ne$StaticEvidence){$StaticEvidence.Start.SHA256}else{$null}
            ConfigTemplateSha256=if($null-ne$StaticEvidence){$StaticEvidence.ConfigTemplate.SHA256}else{$null}
            PrismSha256=if($null-ne$StaticEvidence){$StaticEvidence.Prism.SHA256}else{$null}
            PrismMtimeUtc=if($null-ne$StaticEvidence){$StaticEvidence.Prism.LastWriteTimeUtc}else{$null}
            CaseCount=$Cases.Count
            ExpectedCaseNames=$ExpectedCaseNames
            CaseContractPassed=$CaseContractPassed
            MainCompleted=$MainCompleted
            MainFailure=$FailureText
            EvidenceFailures=@($EvidenceFailures.ToArray())
            OwnedProcesses=$OwnedRecords
            UnverifiedProcessPids=$UnverifiedProcessPids
            RemainingCount=$RemainingCount
            Remaining=$Fresh
            Cleanup=$CleanupEvidence
        }
    }
    $ProvenanceWritten=TryWriteJson (Join-Path $OutputDirectory 'provenance.json') $Provenance 'provenance evidence'
    if(!$ProvenanceWritten){
        $CleanupHealthy=$false
        $Status='FAIL'
        try{$Provenance.Status=$Status;$Provenance.EvidenceFailures=@($EvidenceFailures.ToArray())}catch{RecordEvidenceFailure 'provenance failure update' $_}
        [void](TryWriteText (Join-Path $OutputDirectory 'failure.txt') 'Provider18 provenance write failed; inspect evidence failures.' 'provenance failure evidence')
        $ProvenanceWritten=TryWriteJson (Join-Path $OutputDirectory 'provenance.json') $Provenance 'provenance evidence retry'
    }
    }catch{
        $CleanupHealthy=$false
        $Status='FAIL'
        RecordEvidenceFailure 'unhandled finalization' $_
        if($null-eq$MainFailure){$FailureText=[string]$_}
        [void](TryWriteText (Join-Path $OutputDirectory 'failure.txt') ([string]$FailureText) 'unhandled finalization evidence')
        try{
            if($null-ne$Provenance){$Provenance.Status='FAIL'}else{$Provenance=[ordered]@{Schema='Provider18Evidence/v2';Status='FAIL';EvidenceTimeUtc=$FinalEvidenceTimeUtc;NaturalMainExitClaim=$false;IdentityEvidenceBoundary=$ProcessIdentityEvidenceBoundary;EpochMarker=$EpochMarker;SourceBinaryProvenance=[ordered]@{Status='missing';Boundary='Source manifest and Prism SHA256 are recorded independently; no source-to-binary build mapping is asserted.'};Artifacts=$StaticEvidence;SourceManifestPath=if($null-ne$SourceManifestPath){[IO.Path]::GetFullPath($SourceManifestPath)}else{$null};SourceManifestSha256=if($null-ne$SourceManifest){$SourceManifest.ManifestSha256}else{$null};RunnerSha256=if($null-ne$StaticEvidence){$StaticEvidence.Runner.SHA256}else{$null};PrismMainSha256=if($null-ne$StaticEvidence){$StaticEvidence.PrismMain.SHA256}else{$null};StartSha256=if($null-ne$StaticEvidence){$StaticEvidence.Start.SHA256}else{$null};ConfigTemplateSha256=if($null-ne$StaticEvidence){$StaticEvidence.ConfigTemplate.SHA256}else{$null};PrismSha256=if($null-ne$StaticEvidence){$StaticEvidence.Prism.SHA256}else{$null};CaseCount=$Cases.Count;ExpectedCaseNames=$ExpectedCaseNames;CaseContractPassed=$CaseContractPassed;MainCompleted=$MainCompleted;MainFailure=$FailureText;EvidenceFailures=@($EvidenceFailures.ToArray());OwnedProcesses=$OwnedRecords;UnverifiedProcessPids=$UnverifiedProcessPids;RemainingCount=$RemainingCount;Remaining=$Fresh;Cleanup=$CleanupEvidence}}
            [void](TryWriteJson (Join-Path $OutputDirectory 'provenance.json') $Provenance 'unhandled finalization provenance')
        }catch{RecordEvidenceFailure 'unhandled finalization provenance fallback' $_}
    }
}
Write-Output ('Provider Application interop '+$Status+'; cases='+$Cases.Count)
Write-Output ('Provider18 evidence; NaturalMainExitClaim=false; Operations='+$(if($OperationsSummary.AllDisabled){'disabled'}elseif($EnabledConfigurations.Count){'enabled'}else{'unknown'})+'; Remaining='+$RemainingCount+'; EvidenceTimeUtc='+$FinalEvidenceTimeUtc+'; provenance='+[IO.Path]::GetFullPath((Join-Path $OutputDirectory 'provenance.json')))
$FinalFailure=$null
if($null-ne$MainFailure){$FinalFailure=$MainFailure.Exception}
elseif($Status-ne 'PASS'){$FinalFailure=[InvalidOperationException]::new('Provider18 runner failed during cleanup or evidence finalization')}
if($null-ne$FinalFailure){throw $FinalFailure}
