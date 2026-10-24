Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-MihomoExecutable {
    param([Parameter(Mandatory = $true)][string]$Executable)

    return Resolve-MihomoExecutablePath $Executable
}

function Resolve-MihomoExecutablePath {
    param([Parameter(Mandatory = $true)][string]$Executable)

    $HasPathSeparator = $Executable.Contains('\') -or $Executable.Contains('/')
    if ([System.IO.Path]::IsPathRooted($Executable) -or $HasPathSeparator) {
        $FullPath = Assert-MihomoLocalFixedPathRoot $Executable
        $FullPath = Assert-MihomoLocalFixedFilePath $FullPath
        Assert-MihomoStandaloneExecutable $FullPath
        return $FullPath
    }
    Assert-MihomoLocalExecutableSearchPath
    $CommandPath = (Get-Command -Name $Executable -CommandType Application -ErrorAction Stop).Source
    $CommandPath = Assert-MihomoLocalFixedFilePath $CommandPath
    Assert-MihomoStandaloneExecutable $CommandPath
    return $CommandPath
}

function Assert-MihomoStandaloneExecutable {
    param([Parameter(Mandatory = $true)][string]$Path)

    $FileName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    if ([string]::Equals($FileName, 'verge-mihomo',
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $FileName.StartsWith('clash-verge',
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mihomo interop must use a standalone executable owned by this run, not the user Clash/Verge process binary'
    }
}

function Assert-MihomoLocalFixedPathRoot {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.OperatingSystem]::IsWindows()) {
        throw 'Mihomo interop input paths require Windows local-volume checks'
    }
    if ([System.IO.Path]::IsPathRooted($Path) -and
        -not [System.IO.Path]::IsPathFullyQualified($Path)) {
        throw 'Mihomo interop input paths cannot use drive-relative or root-relative forms'
    }
    $FullPath = [System.IO.Path]::GetFullPath($Path)
    if ($FullPath.StartsWith('\\', [System.StringComparison]::Ordinal) -or
        $FullPath -notmatch '^[A-Za-z]:\\') {
        throw 'Mihomo interop input paths must use a local fixed volume'
    }
    $Root = [System.IO.Path]::GetPathRoot($FullPath)
    $Drive = [System.IO.DriveInfo]::new($Root)
    if ($Drive.DriveType -ne [System.IO.DriveType]::Fixed) {
        throw 'Mihomo interop input paths must use a local fixed volume'
    }
    if (-not $Drive.IsReady) {
        throw 'Mihomo interop input paths must use a ready local fixed volume'
    }
    return $FullPath
}

function Assert-MihomoLocalExecutableSearchPath {
    foreach ($Entry in @(([string]$env:PATH).Split(';'))) {
        $PathValue = [System.Environment]::ExpandEnvironmentVariables($Entry.Trim().Trim('"'))
        if ([string]::IsNullOrWhiteSpace($PathValue)) {
            continue
        }
        $FullPath = Assert-MihomoLocalFixedPathRoot $PathValue
        $Root = [System.IO.Path]::GetPathRoot($FullPath)
        $Current = $Root
        $Parts = @($FullPath.Substring($Root.Length).Split('\',
                [System.StringSplitOptions]::RemoveEmptyEntries))
        foreach ($Part in $Parts) {
            $Current = Join-Path $Current $Part
            try {
                $Item = Get-Item -LiteralPath $Current -Force -ErrorAction Stop
            }
            catch {
                if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound) {
                    break
                }
                throw 'Executable search paths must be readable local directories'
            }
            if (-not $Item.PSIsContainer -or
                ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Executable search paths cannot pass through non-directory or reparse entries'
            }
        }
    }
}

function Assert-MihomoLocalFixedFilePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.OperatingSystem]::IsWindows()) {
        throw 'Mihomo interop input files require Windows local-volume checks'
    }
    try {
        $FullPath = Assert-MihomoLocalFixedPathRoot $Path
        $Root = [System.IO.Path]::GetPathRoot($FullPath)
        $Current = $Root
        $Parts = @($FullPath.Substring($Root.Length).Split('\',
                [System.StringSplitOptions]::RemoveEmptyEntries))
        if ($Parts.Count -eq 0) {
            throw 'path is not a file'
        }
        for ($Index = 0; $Index -lt $Parts.Count; $Index++) {
            $Current = Join-Path $Current $Parts[$Index]
            $Item = Get-Item -LiteralPath $Current -Force -ErrorAction Stop
            if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'reparse point'
            }
            if ($Index -lt ($Parts.Count - 1) -and -not $Item.PSIsContainer) {
                throw 'non-directory parent'
            }
            if ($Index -eq ($Parts.Count - 1) -and $Item.PSIsContainer) {
                throw 'directory instead of file'
            }
        }
        return $FullPath
    }
    catch {
        throw 'Mihomo interop input paths must resolve to regular files on a local fixed volume without reparse points'
    }
}

function New-MihomoPrivateCaseDirectorySecurity {
    if (-not [System.OperatingSystem]::IsWindows()) {
        throw 'Mihomo interop case directories require Windows ACL support'
    }
    $CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $CurrentSid) {
        throw 'Unable to resolve the current Windows user SID for case directory access'
    }
    $AllowedSids = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [void]$AllowedSids.Add($CurrentSid.Value)
    [void]$AllowedSids.Add('S-1-5-18')
    [void]$AllowedSids.Add('S-1-5-32-544')
    $Acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $Acl.SetOwner($CurrentSid)
    $Acl.SetAccessRuleProtection($true, $false)
    $Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($SidText in $AllowedSids) {
        $Rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($SidText),
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $Inheritance, [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$Acl.AddAccessRule($Rule)
    }
    return $Acl
}

function New-MihomoDirectoryCreationApi {
    if ('PrismInterop.MihomoDirectoryCreation' -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace PrismInterop
{
    public static class MihomoDirectoryCreation
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern bool CreateDirectoryWindows(
            string Path, ref SecurityAttributes Attributes);

        public static bool CreateDirectoryExclusive(string Path, byte[] SecurityDescriptor)
        {
            var Pin = GCHandle.Alloc(SecurityDescriptor, GCHandleType.Pinned);
            try
            {
                var Attributes = new SecurityAttributes
                {
                    Length = Marshal.SizeOf<SecurityAttributes>(),
                    SecurityDescriptor = Pin.AddrOfPinnedObject(),
                    InheritHandle = false
                };
                if (CreateDirectoryWindows(Path, ref Attributes))
                {
                    return true;
                }
                var Error = Marshal.GetLastWin32Error();
                if (Error == 80 || Error == 183)
                {
                    return false;
                }
                throw new Win32Exception(Error);
            }
            finally
            {
                Pin.Free();
            }
        }
    }
}
'@ -ErrorAction Stop | Out-Null
}

function Remove-MihomoUnclaimedCaseDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{32}$')][string]$Token
    )

    $FullPath = [System.IO.Path]::GetFullPath($Path)
    $Parent = Split-Path -Parent $FullPath
    $Leaf = Split-Path -Leaf $FullPath
    if (-not [string]::Equals($Parent.TrimEnd([System.IO.Path]::DirectorySeparatorChar), 'H:',
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $Leaf -notmatch ('^PrismInteropResults-' + [regex]::Escape($Token) + '-[A-Za-z0-9_.-]{1,48}$')) {
        throw 'Unclaimed output directory is outside its invocation-specific H:\ path'
    }
    if (-not (Test-Path -LiteralPath $FullPath)) {
        return $true
    }
    $Item = Get-Item -LiteralPath $FullPath -Force -ErrorAction Stop
    if (-not $Item.PSIsContainer -or
        ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Unclaimed output root is not a regular directory'
    }
    Assert-MihomoPrivateCaseDirectory $FullPath
    if (@(Get-ChildItem -LiteralPath $FullPath -Force -ErrorAction Stop).Count -ne 0) {
        throw 'Unclaimed output root contains data and cannot be rolled back'
    }
    [System.IO.Directory]::Delete($FullPath, $false)
    if (Test-Path -LiteralPath $FullPath) {
        throw 'Unclaimed output root remained after non-recursive rollback'
    }
    return $true
}

function Assert-MihomoPrivateCaseDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.OperatingSystem]::IsWindows()) {
        throw 'Mihomo interop case directories require Windows ACL support'
    }
    $Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $Item.PSIsContainer -or
        ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Mihomo case output root must be a regular directory'
    }
    $Acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $Acl.AreAccessRulesProtected) {
        throw 'Mihomo case output root must not inherit shared parent permissions'
    }
    $CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $CurrentSid) {
        throw 'Unable to resolve the current Windows user SID for case directory access'
    }
    $OwnerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    if (-not [string]::Equals($OwnerSid.Value, $CurrentSid.Value,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mihomo case output root must be owned by the current user'
    }
    $AllowedSids = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [void]$AllowedSids.Add($CurrentSid.Value)
    [void]$AllowedSids.Add('S-1-5-18')
    [void]$AllowedSids.Add('S-1-5-32-544')
    $Rules = @($Acl.GetAccessRules($true, $true,
        [System.Security.Principal.SecurityIdentifier]))
    if ($Rules.Count -ne $AllowedSids.Count) {
        throw 'Mihomo case output root must grant access only to its user, SYSTEM, and Administrators'
    }
    $SeenSids = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($Rule in $Rules) {
        $Sid = $Rule.IdentityReference.Value
        if (-not $AllowedSids.Contains($Sid) -or -not $SeenSids.Add($Sid) -or
            $Rule.IsInherited -or
            $Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $Rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $Rule.InheritanceFlags -ne $Inheritance -or
            $Rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
            throw 'Mihomo case output root has an unexpected access rule'
        }
    }
    if ($SeenSids.Count -ne $AllowedSids.Count) {
        throw 'Mihomo case output root is missing a required private access rule'
    }
}

function Assert-MihomoCasePathAccess {
    param([Parameter(Mandatory = $true)][string]$Path)

    $CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $AllowedSids = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [void]$AllowedSids.Add($CurrentSid.Value)
    [void]$AllowedSids.Add('S-1-5-18')
    [void]$AllowedSids.Add('S-1-5-32-544')
    $Acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $OwnerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    if (-not [string]::Equals($OwnerSid.Value, $CurrentSid.Value,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mihomo case artifact must be owned by the current user'
    }
    foreach ($Rule in $Acl.GetAccessRules($true, $true,
            [System.Security.Principal.SecurityIdentifier])) {
        if (-not $AllowedSids.Contains($Rule.IdentityReference.Value)) {
            throw 'Mihomo case artifact inherits access outside its private case principals'
        }
    }
}

function Assert-MihomoLocalFixedDirectoryPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not [System.OperatingSystem]::IsWindows()) {
        throw 'Mihomo interop output requires Windows local-volume checks'
    }
    $FullPath = Assert-MihomoLocalFixedPathRoot $Path
    $Root = [System.IO.Path]::GetPathRoot($FullPath)
    $RootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (-not $RootItem.PSIsContainer -or
        ($RootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Mihomo output root must not pass through a reparse point'
    }
    $Current = $Root
    $Parts = @($FullPath.Substring($Root.Length).Split('\',
            [System.StringSplitOptions]::RemoveEmptyEntries))
    foreach ($Part in $Parts) {
        $Current = Join-Path $Current $Part
        $Item = Get-Item -LiteralPath $Current -Force -ErrorAction Stop
        if (-not $Item.PSIsContainer -or
            ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Mihomo output ancestry must contain only regular local directories'
        }
    }
}

function Assert-MihomoResultsParent {
    $ResultsParent = 'H:\'
    Assert-MihomoLocalFixedDirectoryPath $ResultsParent
    $CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $CurrentSid) {
        throw 'Unable to resolve the current Windows user SID for case directory access'
    }
    $TrustedSids = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    [void]$TrustedSids.Add($CurrentSid.Value)
    [void]$TrustedSids.Add('S-1-5-18')
    [void]$TrustedSids.Add('S-1-5-32-544')
    $ParentAcl = Get-Acl -LiteralPath $ResultsParent -ErrorAction Stop
    $DeleteChild = [long][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    foreach ($Rule in $ParentAcl.GetAccessRules($true, $true,
            [System.Security.Principal.SecurityIdentifier])) {
        if ($Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            -not $TrustedSids.Contains($Rule.IdentityReference.Value) -and
            (([long]$Rule.FileSystemRights -band $DeleteChild) -ne 0)) {
            throw 'H:\ permissions allow a non-private principal to delete child directories'
        }
    }
}

function Assert-MihomoCaseClaim {
    param([Parameter(Mandatory = $true)][string]$CaseRoot)

    $DirectorySeparators = [char[]]@('\', '/')
    $FullCaseRoot = [System.IO.Path]::GetFullPath($CaseRoot).TrimEnd($DirectorySeparators)
    $Parent = Split-Path -Parent $FullCaseRoot
    if (-not [string]::Equals($Parent.TrimEnd($DirectorySeparators), 'H:',
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mihomo case root must be a direct child of H:\'
    }
    $Leaf = Split-Path -Leaf $FullCaseRoot
    if ($Leaf -notmatch '^PrismInteropResults-(?<token>[0-9a-f]{32})-[A-Za-z0-9_.-]{1,48}$') {
        throw 'Mihomo case root name does not carry an invocation token'
    }
    $TokenFromName = $Matches['token']
    $ClaimPath = Join-Path $FullCaseRoot '.mihomo-case-claim'
    $ClaimItem = Get-Item -LiteralPath $ClaimPath -Force -ErrorAction Stop
    if ($ClaimItem.PSIsContainer -or
        ($ClaimItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Mihomo case claim must be a regular file'
    }
    Assert-MihomoCasePathAccess $ClaimPath
    $Token = [System.IO.File]::ReadAllText($ClaimPath, [System.Text.Encoding]::ASCII)
    if (-not [string]::Equals($Token, $TokenFromName, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mihomo case claim token does not match its private output root'
    }
}

function Assert-MihomoCaseArtifactPath {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $SafePath = Resolve-MihomoCaseChildPath $CaseDirectory $Path
    $Current = if (Test-Path -LiteralPath $SafePath) {
        $SafePath
    }
    else {
        Split-Path -Parent $SafePath
    }
    $CaseRoot = [System.IO.Path]::GetFullPath($CaseDirectory)
    while ($Current.StartsWith($CaseRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $Current) {
            Assert-MihomoCasePathAccess $Current
        }
        if ([string]::Equals($Current.TrimEnd([char[]]@('\\', '/')),
                $CaseRoot.TrimEnd([char[]]@('\\', '/')),
                [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $Current = Split-Path -Parent $Current
    }
    return $SafePath
}

function Get-MihomoCaseArtifactPath {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$Path
    )

    return Assert-MihomoCaseArtifactPath $CaseDirectory $Path
}

function New-MihomoCaseSubdirectory {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ([System.IO.Path]::GetFileName($Name) -ne $Name -or
        [string]::IsNullOrWhiteSpace($Name)) {
        throw 'Mihomo case subdirectory name must be a single child name'
    }
    $Path = Assert-MihomoCaseArtifactPath $CaseDirectory (Join-Path $CaseDirectory $Name)
    if (Test-Path -LiteralPath $Path) {
        throw 'Mihomo case subdirectory already exists'
    }
    New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
    $Path = Assert-MihomoCaseArtifactPath $CaseDirectory $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw 'Mihomo case subdirectory was not created as a directory'
    }
    return $Path
}

function New-UniqueMihomoCaseDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9_.-]{1,48}$')]
        [string]$CaseLabel
    )

    if (-not [System.OperatingSystem]::IsWindows()) {
        throw 'Current Mihomo interop runners require Windows filesystem ACLs and socket ownership APIs'
    }
    Assert-MihomoResultsParent
    $CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $CurrentSid) {
        throw 'Unable to resolve the current Windows user SID for case directory access'
    }
    $Token = [guid]::NewGuid().ToString('N')
    $RequestedPath = Join-Path 'H:\' ("PrismInteropResults-{0}-{1}" -f $Token, $CaseLabel)
    if (Test-Path -LiteralPath $RequestedPath) {
        throw 'Mihomo invocation output path already exists; refusing to reuse it'
    }

    $Claimed = $false
    $DirectoryCreated = $false
    $ClaimPath = Join-Path $RequestedPath '.mihomo-case-claim'
    $ClaimStream = $null
    try {
        $DirectorySecurity = New-MihomoPrivateCaseDirectorySecurity
        New-MihomoDirectoryCreationApi
        $CreatedExclusively = [PrismInterop.MihomoDirectoryCreation]::CreateDirectoryExclusive(
            $RequestedPath, $DirectorySecurity.GetSecurityDescriptorBinaryForm())
        if (-not $CreatedExclusively) {
            throw 'Mihomo invocation output path already exists; refusing to reuse it'
        }
        $DirectoryCreated = $true
        $Created = (Resolve-Path -LiteralPath $RequestedPath).Path
        $CreatedItem = Get-Item -LiteralPath $Created -Force -ErrorAction Stop
        if (($CreatedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Created Mihomo output root unexpectedly resolves to a reparse point'
        }
        if (@(Get-ChildItem -LiteralPath $Created -Force -ErrorAction Stop).Count -ne 0) {
            throw 'New Mihomo output root must be empty before the runner writes artifacts'
        }

        $ClaimStream = [System.IO.FileStream]::new(
            $ClaimPath, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $Claimed = $true
        $TokenBytes = [System.Text.Encoding]::ASCII.GetBytes($Token)
        $ClaimStream.Write($TokenBytes, 0, $TokenBytes.Length)
        $ClaimStream.Flush($true)
        $ClaimStream.Dispose()
        $ClaimStream = $null
        Assert-MihomoPrivateCaseDirectory $Created
        Assert-MihomoCaseClaim $Created
        return $Created
    }
    catch {
        $OriginalFailure = $_.Exception
        if ($null -ne $ClaimStream) {
            $ClaimStream.Dispose()
        }
        if ($Claimed) {
            try {
                $CreatedItem = Get-Item -LiteralPath $RequestedPath -Force -ErrorAction Stop
                $CreatedAcl = Get-Acl -LiteralPath $RequestedPath -ErrorAction Stop
                $CreatedOwner = $CreatedAcl.GetOwner(
                    [System.Security.Principal.SecurityIdentifier]).Value
                $OnlyClaim = @(Get-ChildItem -LiteralPath $RequestedPath -Force -ErrorAction Stop)
                if (($CreatedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
                    [string]::Equals($CreatedOwner, $CurrentSid.Value,
                        [System.StringComparison]::OrdinalIgnoreCase) -and
                    $OnlyClaim.Count -eq 1 -and
                    [string]::Equals($OnlyClaim[0].FullName, $ClaimPath,
                        [System.StringComparison]::OrdinalIgnoreCase) -and
                    ($OnlyClaim[0].Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
                    Remove-Item -LiteralPath $ClaimPath -Force -ErrorAction Stop
                    [System.IO.Directory]::Delete($RequestedPath, $false)
                    if (Test-Path -LiteralPath $RequestedPath) {
                        throw 'claimed output root remained after non-recursive rollback'
                    }
                }
                else {
                    throw 'owned output root is no longer empty and safely removable'
                }
            }
            catch {
                throw "Mihomo output root initialization failed and safe rollback could not be verified; the path was retained: $RequestedPath"
            }
        }
        elseif ($DirectoryCreated) {
            try {
                [void](Remove-MihomoUnclaimedCaseDirectory $RequestedPath $Token)
            }
            catch {
                throw "Mihomo output root initialization failed before claim; safe non-recursive rollback could not be verified and the path was retained: $RequestedPath"
            }
        }
        throw $OriginalFailure
    }
}

function Resolve-MihomoCaseChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $DirectorySeparators = [char[]]@('\', '/')
    $CaseRoot = [System.IO.Path]::GetFullPath($CaseDirectory).TrimEnd($DirectorySeparators)
    $ResultsRoot = Split-Path -Parent $CaseRoot
    if (-not [string]::Equals($ResultsRoot.TrimEnd($DirectorySeparators), 'H:',
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Owned Mihomo output root must remain a direct child of H:\'
    }
    Assert-MihomoResultsParent
    foreach ($OwnedRoot in @($ResultsRoot, $CaseRoot)) {
        if (-not (Test-Path -LiteralPath $OwnedRoot -PathType Container)) {
            throw "Owned cleanup root is missing: $OwnedRoot"
        }
        $RootItem = Get-Item -LiteralPath $OwnedRoot -Force -ErrorAction Stop
        if (($RootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Owned cleanup root contains a reparse point: $OwnedRoot"
        }
    }
    $Candidate = [System.IO.Path]::GetFullPath($Path)
    $Prefix = $CaseRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $Candidate.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Automatic cleanup path is outside the owned CaseDirectory: $Path"
    }

    $Current = $Candidate
    while ($Current.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force -ErrorAction Stop
            if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Automatic cleanup path contains a reparse point: $Current"
            }
            Assert-MihomoCasePathAccess $Current
        }
        $Parent = Split-Path -Parent $Current
        if ([string]::Equals($Parent.TrimEnd($DirectorySeparators), $CaseRoot,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        if ([string]::IsNullOrWhiteSpace($Parent) -or $Parent -eq $Current) {
            throw "Unable to verify automatic cleanup path: $Path"
        }
        $Current = $Parent
    }
    Assert-MihomoPrivateCaseDirectory $CaseRoot
    Assert-MihomoCaseClaim $CaseRoot
    return $Candidate
}

function Remove-MihomoCaseFile {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $SafePath = Resolve-MihomoCaseChildPath $CaseDirectory $Path
    if (-not (Test-Path -LiteralPath $SafePath)) {
        return $true
    }
    if (Test-Path -LiteralPath $SafePath -PathType Container) {
        throw "Expected an owned temporary file: $SafePath"
    }
    Remove-Item -LiteralPath $SafePath -Force -ErrorAction Stop
    return -not (Test-Path -LiteralPath $SafePath)
}

function Remove-MihomoCaseDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $SafePath = Resolve-MihomoCaseChildPath $CaseDirectory $Path
    if (-not (Test-Path -LiteralPath $SafePath)) {
        return $true
    }
    if (-not (Test-Path -LiteralPath $SafePath -PathType Container)) {
        throw "Expected an owned temporary directory: $SafePath"
    }
    $NestedReparsePoints = @(Get-ChildItem -LiteralPath $SafePath -Force -Recurse -ErrorAction Stop |
        Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 })
    if ($NestedReparsePoints.Count -gt 0) {
        throw "Temporary cleanup directory contains a reparse point: $SafePath"
    }
    for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
        try {
            Remove-Item -LiteralPath $SafePath -Recurse -Force -ErrorAction Stop
            return -not (Test-Path -LiteralPath $SafePath)
        }
        catch {
            if ($Attempt -eq 29) {
                throw
            }
            Start-Sleep -Milliseconds 250
        }
    }
    return $false
}

function Register-MihomoOwnedProcess {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$Registry,
        [Parameter(Mandatory = $true)][System.Diagnostics.Process]$ProcessValue,
        [Parameter(Mandatory = $true)][string]$ExecutablePath
    )

    $ProcessId = $null
    try {
        $ProcessId = $ProcessValue.Id
    }
    catch {
    }
    $Owner = [pscustomobject]@{
        Process = $ProcessValue
        Id = $ProcessId
        RequestedPath = $ExecutablePath
        Path = ''
        StartTimeUtc = $null
        Stopped = $false
    }
    [void]$Registry.Add($Owner)
    if (-not (Initialize-MihomoOwnedProcessIdentity $Owner)) {
        throw "Unable to capture started process identity: $ExecutablePath"
    }
    if ($Owner.Stopped) {
        return $Owner
    }
    if (-not (Test-MihomoOwnedProcessIdentity $Owner)) {
        throw "Started process identity does not match its requested executable: $ExecutablePath"
    }
    return $Owner
}

function Initialize-MihomoOwnedProcessIdentity {
    param([Parameter(Mandatory = $true)][psobject]$Owner)

    try {
        if ($null -eq $Owner.Id) {
            $Owner.Id = $Owner.Process.Id
        }
        $Owner.Process.Refresh()
        if ($Owner.Process.HasExited) {
            $Owner.Stopped = $true
            return $true
        }
        if ([string]::IsNullOrWhiteSpace($Owner.Path)) {
            if ([System.IO.Path]::IsPathRooted($Owner.RequestedPath)) {
                try {
                    $Owner.Path = Resolve-MihomoExecutablePath $Owner.RequestedPath
                }
                catch {
                    $Owner.Path = [System.IO.Path]::GetFullPath($Owner.RequestedPath)
                }
            }
            else {
                $Owner.Path = Resolve-MihomoExecutablePath $Owner.RequestedPath
            }
        }
        $Owner.Path = [System.IO.Path]::GetFullPath($Owner.Path)
        if ($null -eq $Owner.StartTimeUtc) {
            $Owner.StartTimeUtc = $Owner.Process.StartTime.ToUniversalTime()
        }
        return $null -ne $Owner.StartTimeUtc
    }
    catch {
        return $false
    }
}

function Test-MihomoOwnedProcessIdentity {
    param([Parameter(Mandatory = $true)][psobject]$Owner)

    if ($null -eq $Owner.Id -or [string]::IsNullOrWhiteSpace($Owner.Path) -or
        $null -eq $Owner.StartTimeUtc) {
        return $false
    }
    try {
        $Owner.Process.Refresh()
        if ($Owner.Process.HasExited) {
            $Owner.Stopped = $true
            return $false
        }
    }
    catch {
        return $false
    }
    $Current = Get-Process -Id $Owner.Id -ErrorAction SilentlyContinue
    if ($null -eq $Current -or [string]::IsNullOrWhiteSpace($Current.Path)) {
        return $false
    }
    try {
        $CurrentPath = [System.IO.Path]::GetFullPath($Current.Path)
        $CurrentStartTime = $Current.StartTime.ToUniversalTime()
    }
    catch {
        return $false
    }
    return [string]::Equals($CurrentPath, $Owner.Path,
            [System.StringComparison]::OrdinalIgnoreCase) -and
        $CurrentStartTime.Ticks -eq $Owner.StartTimeUtc.Ticks
}

function Test-MihomoLoopbackAddress {
    param([Parameter(Mandatory = $true)][string]$Address)

    $ParsedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ParsedAddress)) {
        return $false
    }
    if ($ParsedAddress.IsIPv4MappedToIPv6) {
        $ParsedAddress = $ParsedAddress.MapToIPv4()
    }
    return [System.Net.IPAddress]::IsLoopback($ParsedAddress)
}

function Assert-MihomoTemplateProxyEndpointsAreLoopback {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [string]$LocalAlias = 'socks5.preview'
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    foreach ($Proxy in (Get-MihomoProxyEntries $Yaml)) {
        $Server = Get-MihomoProxyScalar $Yaml $Proxy.Name 'server'
        if ([string]::Equals($Server, $LocalAlias,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        if (-not (Test-MihomoLoopbackAddress $Server)) {
            throw 'Mihomo template proxy servers must use an explicit loopback address or local fixture alias'
        }
    }
}

function Test-MihomoAddressMatchesExpectedLoopback {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][string]$ExpectedAddress
    )

    $ParsedAddress = $null
    $ParsedExpectedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ParsedAddress) -or
        -not [System.Net.IPAddress]::TryParse($ExpectedAddress, [ref]$ParsedExpectedAddress)) {
        return $false
    }
    if ($ParsedAddress.IsIPv4MappedToIPv6) {
        $ParsedAddress = $ParsedAddress.MapToIPv4()
    }
    if ($ParsedExpectedAddress.IsIPv4MappedToIPv6) {
        $ParsedExpectedAddress = $ParsedExpectedAddress.MapToIPv4()
    }
    return [System.Net.IPAddress]::IsLoopback($ParsedAddress) -and
        [System.Net.IPAddress]::IsLoopback($ParsedExpectedAddress) -and
        $ParsedAddress.Equals($ParsedExpectedAddress)
}

function Resolve-MihomoTemplatePath {
    param(
        [AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][string]$BaseDirectory
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }
    if ([System.IO.Path]::IsPathFullyQualified($Value)) {
        return Assert-MihomoLocalFixedFilePath ([System.IO.Path]::GetFullPath($Value))
    }
    if ([System.IO.Path]::IsPathRooted($Value)) {
        throw 'Prism template path is rooted but not fully qualified'
    }
    return Assert-MihomoLocalFixedFilePath (
        [System.IO.Path]::GetFullPath((Join-Path $BaseDirectory $Value)))
}

function Resolve-MihomoPrismLocalPaths {
    param(
        [Parameter(Mandatory = $true)][object]$Configuration,
        [Parameter(Mandatory = $true)][string]$TemplateDirectory
    )

    if ($Configuration.Operations -and
        $Configuration.Operations.PSObject.Properties.Name -contains 'WebDirectory') {
        $Configuration.Operations.WebDirectory = ''
    }
    if ($Configuration.NativeTls -and $Configuration.NativeTls.Ech) {
        $Configuration.NativeTls.Ech.Enabled = $false
        $Configuration.NativeTls.Ech.PrivateKeyFile = ''
        $Configuration.NativeTls.Ech.EchConfigFile = ''
    }
    if ($Configuration.NativeTls) {
        foreach ($PropertyName in @('CertificateFile', 'PrivateKeyFile')) {
            $Value = [string]$Configuration.NativeTls.$PropertyName
            if (-not [string]::IsNullOrWhiteSpace($Value)) {
                $Configuration.NativeTls.$PropertyName = Resolve-MihomoTemplatePath `
                    $Value $TemplateDirectory
            }
        }
    }
    foreach ($Carrier in @($Configuration.Carriers)) {
        $Options = $Carrier.Options
        if ($null -eq $Options) {
            continue
        }
        foreach ($PropertyName in @('CertificateFile', 'PrivateKeyFile')) {
            if ($Options.PSObject.Properties.Name -contains $PropertyName) {
                $Value = [string]$Options.$PropertyName
                if (-not [string]::IsNullOrWhiteSpace($Value)) {
                    $Options.$PropertyName = Resolve-MihomoTemplatePath `
                        $Value $TemplateDirectory
                }
            }
        }
    }
}

function Assert-MihomoPrismLocalPaths {
    param([Parameter(Mandatory = $true)][object]$Configuration)

    if ($null -ne $Configuration.Operations.WebDirectory -and
        -not [string]::IsNullOrEmpty([string]$Configuration.Operations.WebDirectory)) {
        throw 'Prism case configuration must not retain an Operations WebDirectory path'
    }
    $Ech = $Configuration.NativeTls.Ech
    if ($Ech.Enabled -or -not [string]::IsNullOrEmpty([string]$Ech.PrivateKeyFile) -or
        -not [string]::IsNullOrEmpty([string]$Ech.EchConfigFile)) {
        throw 'Prism case configuration must not retain ECH file inputs'
    }
    foreach ($PropertyName in @('CertificateFile', 'PrivateKeyFile')) {
        $Value = [string]$Configuration.NativeTls.$PropertyName
        if (-not [string]::IsNullOrWhiteSpace($Value)) {
            [void](Assert-MihomoLocalFixedFilePath $Value)
        }
    }
    foreach ($Carrier in @($Configuration.Carriers)) {
        $Options = $Carrier.Options
        if ($null -eq $Options) {
            continue
        }
        foreach ($PropertyName in @('CertificateFile', 'PrivateKeyFile')) {
            if ($Options.PSObject.Properties.Name -contains $PropertyName) {
                $Value = [string]$Options.$PropertyName
                if (-not [string]::IsNullOrWhiteSpace($Value)) {
                    [void](Assert-MihomoLocalFixedFilePath $Value)
                }
            }
        }
    }
}

function Assert-MihomoPrismCaseLogging {
    param(
        [Parameter(Mandatory = $true)][object]$Configuration,
        [Parameter(Mandatory = $true)][string]$CaseDirectory
    )

    if (-not [string]::Equals([string]$Configuration.Logging.FileName, 'prism.log',
            [System.StringComparison]::Ordinal)) {
        throw 'Prism case logging must use the fixed prism.log filename'
    }
    $ExpectedDirectory = [System.IO.Path]::GetFullPath(
        (Join-Path $CaseDirectory 'prism-logs'))
    $ConfiguredDirectory = [System.IO.Path]::GetFullPath(
        [string]$Configuration.Logging.Directory)
    if (-not [string]::Equals($ExpectedDirectory, $ConfiguredDirectory,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Prism case logging directory did not read back as the private case directory'
    }
    [void](Assert-MihomoCaseArtifactPath $CaseDirectory $ConfiguredDirectory)
    Assert-MihomoLocalFixedDirectoryPath $ConfiguredDirectory
}

function Get-MihomoActiveDialCarriers {
    param([Parameter(Mandatory = $true)][object]$Configuration)

    $ActiveIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Binding in @($Configuration.ProtocolBindings)) {
        if ($null -eq $Binding -or
            -not ($Binding.PSObject.Properties.Name -contains 'CarrierId')) {
            continue
        }
        if ($null -eq $Binding.CarrierId) {
            continue
        }
        if ($Binding.CarrierId -isnot [string]) {
            throw 'Prism protocol binding contains an invalid carrier reference'
        }
        if (-not [string]::IsNullOrWhiteSpace($Binding.CarrierId)) {
            [void]$ActiveIds.Add($Binding.CarrierId)
        }
    }

    $Result = [System.Collections.Generic.List[object]]::new()
    $SeenIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Carrier in @($Configuration.Carriers)) {
        if ($null -eq $Carrier -or $Carrier.Id -isnot [string]) {
            continue
        }
        if (-not $ActiveIds.Contains($Carrier.Id)) {
            continue
        }
        if (-not $SeenIds.Add($Carrier.Id)) {
            throw 'Prism configuration contains repeated active carrier identifiers'
        }
        $Builtin = ([regex]::Replace([string]$Carrier.Builtin, '[^A-Za-z0-9]', '')).ToLowerInvariant()
        $TargetProperty = switch ($Builtin) {
            'shadowtls' { 'HandshakeDest'; break }
            'restls' { 'Host'; break }
            default { '' }
        }
        if (-not [string]::IsNullOrEmpty($TargetProperty)) {
            $Result.Add([pscustomobject]@{
                Carrier = $Carrier
                TargetProperty = $TargetProperty
            })
        }
    }

    foreach ($ActiveId in $ActiveIds) {
        if (-not $SeenIds.Contains($ActiveId)) {
            throw 'Prism protocol binding references a missing carrier'
        }
    }
    return $Result.ToArray()
}

function Set-MihomoPrismDialCarrierBackend {
    param(
        [Parameter(Mandatory = $true)][object]$Configuration,
        [Parameter(Mandatory = $true)][ValidateRange(0, 65535)][int]$BackendPort
    )

    $DialCarriers = @(Get-MihomoActiveDialCarriers $Configuration)
    if ($DialCarriers.Count -eq 0) {
        return
    }
    if ($BackendPort -le 0) {
        throw 'Active ShadowTLS/Restls carriers require the local handshake backend; no external dial target is allowed'
    }
    $Endpoint = "127.0.0.1:$BackendPort"
    foreach ($Entry in $DialCarriers) {
        $Options = $Entry.Carrier.Options
        if ($null -eq $Options -or
            -not ($Options.PSObject.Properties.Name -contains $Entry.TargetProperty) -or
            $Options.($Entry.TargetProperty) -isnot [string] -or
            [string]::IsNullOrWhiteSpace($Options.($Entry.TargetProperty))) {
            throw 'Active dial-capable carrier has no supported endpoint field'
        }
        $Options.($Entry.TargetProperty) = $Endpoint
        if (-not [string]::Equals($Options.($Entry.TargetProperty), $Endpoint,
                [System.StringComparison]::Ordinal)) {
            throw 'Active carrier endpoint did not normalize to the local handshake backend'
        }
    }
}

function Assert-MihomoPrismDialCarrierBackend {
    param(
        [Parameter(Mandatory = $true)][object]$Configuration,
        [Parameter(Mandatory = $true)][ValidateRange(0, 65535)][int]$BackendPort
    )

    $DialCarriers = @(Get-MihomoActiveDialCarriers $Configuration)
    if ($DialCarriers.Count -eq 0) {
        return
    }
    if ($BackendPort -le 0) {
        throw 'Prism readback contains an active carrier capable of external dialing'
    }
    $ExpectedEndpoint = "127.0.0.1:$BackendPort"
    foreach ($Entry in $DialCarriers) {
        $Options = $Entry.Carrier.Options
        if ($null -eq $Options -or
            -not ($Options.PSObject.Properties.Name -contains $Entry.TargetProperty) -or
            $Options.($Entry.TargetProperty) -isnot [string] -or
            -not [string]::Equals($Options.($Entry.TargetProperty), $ExpectedEndpoint,
                [System.StringComparison]::Ordinal)) {
            throw 'Prism readback contains an active carrier endpoint outside the local handshake backend'
        }
    }
}

function Assert-MihomoCurlArgumentsDisableDefaults {
    param([Parameter(Mandatory = $true)][object]$Arguments)

    $ArgumentText = if ($Arguments -is [string]) {
        $Arguments
    }
    else {
        [string]::Join(' ', [string[]]@($Arguments))
    }
    $FirstArgument = [regex]::Match($ArgumentText,
        '^\s*(?:"(?<quoted>[^"]+)"|(?<plain>\S+))')
    $Value = if ($FirstArgument.Groups['quoted'].Success) {
        $FirstArgument.Groups['quoted'].Value
    }
    else {
        $FirstArgument.Groups['plain'].Value
    }
    if (-not [string]::Equals($Value, '-q', [System.StringComparison]::Ordinal)) {
        throw 'Isolated curl requests must disable user curl configuration with first argument -q'
    }
    if ($ArgumentText -notmatch '(?:^|\s)--noproxy(?:=|\s)') {
        throw 'Isolated curl requests must ignore inherited proxy settings with --noproxy'
    }
}

function Assert-MihomoExactResponseBody {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Actual,
        [Parameter(Mandatory = $true)][byte[]]$Expected
    )

    if ($Actual.Length -ne $Expected.Length) {
        throw 'HTTP response body did not match the isolated target fixture'
    }
    for ($Index = 0; $Index -lt $Expected.Length; $Index++) {
        if ($Actual[$Index] -ne $Expected[$Index]) {
            throw 'HTTP response body did not match the isolated target fixture'
        }
    }
}

function Normalize-MihomoLoopbackEndpoint {
    param([Parameter(Mandatory = $true)][System.Net.IPEndPoint]$Endpoint)

    if ($Endpoint.Port -lt 1 -or $Endpoint.Port -gt 65535) {
        throw 'SOCKS5 returned an invalid UDP relay port'
    }
    $Address = $Endpoint.Address
    if ($Address.IsIPv4MappedToIPv6) {
        $Address = $Address.MapToIPv4()
    }
    if ([System.Net.IPAddress]::Any.Equals($Address)) {
        $Address = [System.Net.IPAddress]::Loopback
    }
    elseif ([System.Net.IPAddress]::IPv6Any.Equals($Address)) {
        $Address = [System.Net.IPAddress]::IPv6Loopback
    }
    if (-not ([System.Net.IPAddress]::Loopback.Equals($Address) -or
        [System.Net.IPAddress]::IPv6Loopback.Equals($Address))) {
        throw 'SOCKS5 UDP relay must use the IPv4 or IPv6 loopback address'
    }
    return [System.Net.IPEndPoint]::new($Address, $Endpoint.Port)
}

function Test-MihomoSocks5UdpRelaySource {
    param(
        [Parameter(Mandatory = $true)][System.Net.IPEndPoint]$Relay,
        [Parameter(Mandatory = $true)][System.Net.IPEndPoint]$Source
    )

    $RelayAddress = $Relay.Address
    $SourceAddress = $Source.Address
    if ($RelayAddress.IsIPv4MappedToIPv6) {
        $RelayAddress = $RelayAddress.MapToIPv4()
    }
    if ($SourceAddress.IsIPv4MappedToIPv6) {
        $SourceAddress = $SourceAddress.MapToIPv4()
    }
    $RelayIsLoopback = [System.Net.IPAddress]::Loopback.Equals($RelayAddress) -or
        [System.Net.IPAddress]::IPv6Loopback.Equals($RelayAddress)
    $SourceIsLoopback = [System.Net.IPAddress]::Loopback.Equals($SourceAddress) -or
        [System.Net.IPAddress]::IPv6Loopback.Equals($SourceAddress)
    return $RelayIsLoopback -and $SourceIsLoopback -and
        $Relay.Port -eq $Source.Port -and $RelayAddress.Equals($SourceAddress)
}

function Set-MihomoPrismQuicListeners {
    param(
        [Parameter(Mandatory = $true)][psobject]$Configuration,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$TcpPort,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$QuicPort
    )

    if ($null -eq $Configuration.Listeners) {
        throw 'Prism template must define listener arrays'
    }
    $Tcp = @($Configuration.Listeners.Tcp)
    $Udp = @($Configuration.Listeners.Udp)
    $Quic = @($Configuration.Listeners.Quic)
    if ($Tcp.Count -ne 1 -or $Udp.Count -gt 1 -or $Quic.Count -gt 1) {
        throw 'Prism QUIC template must contain exactly one TCP and no more than one UDP/QUIC listener'
    }
    if ($Udp.Count -eq 0) {
        $Udp = @([pscustomobject]@{
                Id = 'udp-main'; Address = '127.0.0.1'; Port = $QuicPort; Timeout = 5000
            })
    }
    if ($Quic.Count -eq 0) {
        $Quic = @([pscustomobject]@{
                Id = 'quic-main'; Address = '127.0.0.1'; Port = $QuicPort; Timeout = 5000
            })
    }
    $Tcp[0].Address = '127.0.0.1'
    $Tcp[0].Port = $TcpPort
    $Udp[0].Address = '127.0.0.1'
    $Udp[0].Port = $QuicPort
    $Quic[0].Address = '127.0.0.1'
    $Quic[0].Port = $QuicPort
    $Configuration.Listeners.Tcp = @($Tcp[0])
    $Configuration.Listeners.Udp = @($Udp[0])
    $Configuration.Listeners.Quic = @($Quic[0])

    if (@($Configuration.Listeners.Tcp).Count -ne 1 -or
        @($Configuration.Listeners.Udp).Count -ne 1 -or
        @($Configuration.Listeners.Quic).Count -ne 1 -or
        $Configuration.Listeners.Tcp[0].Address -ne '127.0.0.1' -or
        $Configuration.Listeners.Tcp[0].Port -ne $TcpPort -or
        $Configuration.Listeners.Udp[0].Address -ne '127.0.0.1' -or
        $Configuration.Listeners.Udp[0].Port -ne $QuicPort -or
        $Configuration.Listeners.Quic[0].Address -ne '127.0.0.1' -or
        $Configuration.Listeners.Quic[0].Port -ne $QuicPort) {
        throw 'Prism QUIC case listeners are not isolated to their loopback ports'
    }
}

function Set-MihomoPrismCaseListeners {
    param(
        [Parameter(Mandatory = $true)][psobject]$Configuration,
        [Parameter(Mandatory = $true)][ValidateSet('tcp', 'udp')][string]$Mode,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$TcpPort,
        [int]$UdpPort = 0,
        [string]$ListenerAddress = '127.0.0.1'
    )

    if ($null -eq $Configuration.Listeners) {
        throw 'Prism template must define listener arrays'
    }
    if (-not (Test-MihomoLoopbackAddress $ListenerAddress)) {
        throw 'Prism case listener address must be loopback'
    }
    $Tcp = @($Configuration.Listeners.Tcp)
    $Udp = @($Configuration.Listeners.Udp)
    if ($Tcp.Count -eq 0 -or ($Mode -eq 'udp' -and $Udp.Count -eq 0)) {
        throw 'Prism template is missing a listener required by this isolated case'
    }
    if ($Mode -eq 'udp' -and ($UdpPort -lt 1 -or $UdpPort -gt 65535)) {
        throw 'Prism UDP case requires a valid UDP listener port'
    }
    $TcpListener = $Tcp[0]
    $TcpListener.Address = $ListenerAddress
    $TcpListener.Port = $TcpPort
    $Configuration.Listeners.Tcp = @($TcpListener)
    if ($Mode -eq 'udp') {
        $UdpListener = $Udp[0]
        $UdpListener.Address = $ListenerAddress
        $UdpListener.Port = $UdpPort
        $Configuration.Listeners.Udp = @($UdpListener)
    }
    else {
        $Configuration.Listeners.Udp = @()
    }
    $Configuration.Listeners.Quic = @()
}

function Assert-MihomoPrismConfigurationCase {
    param(
        [Parameter(Mandatory = $true)][psobject]$Configuration,
        [Parameter(Mandatory = $true)][ValidateSet('tcp', 'udp', 'quic')][string]$Mode,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$TcpPort,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$OperationsPort,
        [string]$ListenerAddress = '127.0.0.1',
        [ValidateRange(0, 65535)][int]$UdpPort = 0,
        [ValidateRange(0, 65535)][int]$QuicPort = 0,
        [AllowEmptyString()][string]$QuicProtocolId = '',
        [AllowEmptyString()][string]$QuicSecretReference = '',
        [AllowEmptyString()][string]$ExpectedQuicCredential = ''
    )

    if ($null -eq $Configuration.Listeners) {
        throw 'Prism case JSON readback has no listener configuration'
    }
    if (-not (Test-MihomoLoopbackAddress $ListenerAddress)) {
        throw 'Prism case JSON readback listener address must be loopback'
    }
    $Tcp = @($Configuration.Listeners.Tcp)
    $Udp = @($Configuration.Listeners.Udp)
    $Quic = @($Configuration.Listeners.Quic)
    $ExpectedUdpCount = if ($Mode -eq 'udp' -or $Mode -eq 'quic') { 1 } else { 0 }
    $ExpectedQuicCount = if ($Mode -eq 'quic') { 1 } else { 0 }
    if ($Tcp.Count -ne 1 -or $Udp.Count -ne $ExpectedUdpCount -or
        $Quic.Count -ne $ExpectedQuicCount -or
        $Tcp[0].Address -ne $ListenerAddress -or $Tcp[0].Port -ne $TcpPort) {
        throw 'Prism case JSON readback contains an unexpected TCP, UDP, or QUIC listener'
    }
    if ($ExpectedUdpCount -eq 1 -and
        ($Udp[0].Address -ne $ListenerAddress -or
            $Udp[0].Port -ne $(if ($Mode -eq 'quic') { $QuicPort } else { $UdpPort }))) {
        throw 'Prism case JSON readback contains an unexpected UDP listener'
    }
    if ($ExpectedQuicCount -eq 1 -and
        ($Quic[0].Address -ne '127.0.0.1' -or $Quic[0].Port -ne $QuicPort)) {
        throw 'Prism case JSON readback contains an unexpected QUIC listener'
    }
    if ($null -eq $Configuration.Operations -or
        $Configuration.Operations.Endpoint -isnot [string] -or
        $Configuration.Operations.Endpoint -ne "127.0.0.1:$OperationsPort") {
        throw 'Prism case JSON readback contains an unexpected Operations endpoint'
    }
    $OperationsEnabledProperty = $Configuration.Operations.PSObject.Properties['Enabled']
    $ExpectedOperationsEnabled = $Mode -ne 'quic'
    if ($null -eq $OperationsEnabledProperty -or
        $OperationsEnabledProperty.Value -isnot [bool] -or
        $OperationsEnabledProperty.Value -ne $ExpectedOperationsEnabled) {
        throw 'Prism case JSON readback contains an unexpected Operations enabled state'
    }
    if ($Mode -ne 'quic') {
        return
    }

    if ([string]::IsNullOrWhiteSpace($QuicProtocolId) -or
        [string]::IsNullOrWhiteSpace($QuicSecretReference) -or
        [string]::IsNullOrEmpty($ExpectedQuicCredential)) {
        throw 'Prism QUIC case readback requires its selected protocol and secret scope'
    }
    $QuicProtocols = @($Configuration.Protocols | Where-Object {
            $null -ne $_.PSObject.Properties['Quic']
        })
    $Accounts = @($Configuration.Accounts)
    if ($QuicProtocols.Count -ne 1 -or $QuicProtocols[0].Id -ne $QuicProtocolId -or
        $QuicProtocols[0].Quic.CredentialSecretRef -ne $QuicSecretReference -or
        $Accounts.Count -ne 1 -or $Accounts[0].SecretRef -ne $QuicSecretReference) {
        throw 'Prism QUIC case JSON readback has an unexpected protocol or account reference'
    }
    $SecretProperties = @($Configuration.Secrets.PSObject.Properties)
    if ($SecretProperties.Count -ne 1 -or
        $SecretProperties[0].Name -ne $QuicSecretReference -or
        -not [string]::Equals([string]$SecretProperties[0].Value,
            $ExpectedQuicCredential, [System.StringComparison]::Ordinal)) {
        throw 'Prism QUIC case JSON readback has an unexpected secret scope'
    }
    $InlineCredential = $Accounts[0].PSObject.Properties['Credential']
    if ($null -ne $InlineCredential -and -not [string]::IsNullOrEmpty(
            [string]$InlineCredential.Value)) {
        throw 'Prism QUIC case JSON readback contains an inline account credential'
    }
    $AccountCredentials = $Accounts[0].PSObject.Properties['Credentials']
    if ($null -ne $AccountCredentials -and $null -ne $AccountCredentials.Value) {
        $CredentialCount = if ($AccountCredentials.Value -is [System.Collections.IDictionary]) {
            $AccountCredentials.Value.Count
        }
        else {
            @($AccountCredentials.Value.PSObject.Properties).Count
        }
        if ($CredentialCount -ne 0) {
            throw 'Prism QUIC case JSON readback contains extra account credentials'
        }
    }
}

function Assert-MihomoPrismMixedConfigurationCase {
    param(
        [Parameter(Mandatory = $true)][psobject]$Configuration,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$TcpPort,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$UdpPort,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$QuicPort,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$OperationsPort,
        [Parameter(Mandatory = $true)][string]$ListenerAddress
    )

    if (-not (Test-MihomoLoopbackAddress $ListenerAddress)) {
        throw 'Mixed Prism readback listener address must be loopback'
    }
    $Tcp = @($Configuration.Listeners.Tcp)
    $Udp = @($Configuration.Listeners.Udp)
    $Quic = @($Configuration.Listeners.Quic)
    if ($Tcp.Count -ne 1 -or $Udp.Count -ne 1 -or $Quic.Count -ne 1 -or
        $Tcp[0].Address -ne $ListenerAddress -or $Tcp[0].Port -ne $TcpPort -or
        $Udp[0].Address -ne $ListenerAddress -or $Udp[0].Port -ne $UdpPort -or
        $Quic[0].Address -ne $ListenerAddress -or $Quic[0].Port -ne $QuicPort) {
        throw 'Mixed Prism readback contains unexpected TCP, UDP, or QUIC listeners'
    }
    if ($null -eq $Configuration.Operations -or
        $Configuration.Operations.Enabled -ne $true -or
        $Configuration.Operations.Endpoint -ne "127.0.0.1:$OperationsPort") {
        throw 'Mixed Prism readback contains an unexpected Operations endpoint'
    }
    $Hysteria = @($Configuration.Protocols | Where-Object Id -eq 'protocol-hysteria2')
    if ($Hysteria.Count -ne 1 -or $null -eq $Hysteria[0].Quic) {
        throw 'Mixed Prism readback has no Hysteria2 QUIC protocol'
    }
    $SecretReference = [string]$Hysteria[0].Quic.CredentialSecretRef
    $Secret = if ([string]::IsNullOrWhiteSpace($SecretReference)) {
        $null
    } else {
        $Configuration.Secrets.PSObject.Properties[$SecretReference]
    }
    if ($null -eq $Secret -or [string]::IsNullOrEmpty([string]$Secret.Value)) {
        throw 'Mixed Prism readback has no Hysteria2 secret scope'
    }
    if (@($Configuration.Accounts).Count -ne 1 -or
        $null -eq $Configuration.Accounts[0].Credentials) {
        throw 'Mixed Prism readback has no complete account credential set'
    }
}

function Read-MihomoPrismConfigurationReadback {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $Bytes = [System.IO.File]::ReadAllBytes($Path)
        $Encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $JsonText = $Encoding.GetString($Bytes)
        $Configuration = ConvertFrom-Json -InputObject $JsonText -ErrorAction Stop
        if ($null -eq $Configuration -or -not ($Configuration -is [pscustomobject])) {
            throw 'Invalid Prism configuration shape'
        }
        $Sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $Digest = $Sha.ComputeHash($Bytes)
            $Sha256 = [Convert]::ToHexString($Digest).ToUpperInvariant()
        }
        finally {
            [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($Digest)
            $Sha.Dispose()
        }
        return [pscustomobject]@{ Configuration = $Configuration; Sha256 = $Sha256 }
    }
    catch {
        throw 'Prism case configuration could not be read back as a JSON object'
    }
}

function Test-MihomoOwnedTcpPort {
    param(
        [Parameter(Mandatory = $true)][psobject]$Owner,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port,
        [Parameter(Mandatory = $true)][string]$ExpectedLocalAddress
    )

    if (-not (Test-MihomoOwnedProcessIdentity $Owner) -or
        -not (Test-MihomoLoopbackAddress $ExpectedLocalAddress)) {
        return $false
    }
    try {
        $Endpoints = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
    }
    catch {
        return $false
    }
    if ($Endpoints.Count -eq 0) {
        return $false
    }
    foreach ($Endpoint in $Endpoints) {
        if ($Endpoint.OwningProcess -ne $Owner.Id -or
            -not (Test-MihomoAddressMatchesExpectedLoopback `
                ([string]$Endpoint.LocalAddress) $ExpectedLocalAddress)) {
            return $false
        }
    }
    return $true
}

function Assert-MihomoTcpPortNotOwned {
    param(
        [Parameter(Mandatory = $true)][psobject]$Owner,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port
    )

    if (-not (Test-MihomoOwnedProcessIdentity $Owner)) {
        throw 'The owned Prism process identity is unavailable while checking disabled Operations'
    }
    try {
        $Endpoints = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
    }
    catch {
        throw 'Unable to inspect TCP listener ownership for disabled Operations'
    }
    if (@($Endpoints | Where-Object {
                $_.LocalPort -eq $Port -and $_.OwningProcess -eq $Owner.Id
            }).Count -gt 0) {
        throw 'Prism opened the Operations endpoint although Operations is disabled'
    }
}

function Test-MihomoOwnedUdpPort {
    param(
        [Parameter(Mandatory = $true)][psobject]$Owner,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port,
        [Parameter(Mandatory = $true)][string]$ExpectedLocalAddress
    )

    if (-not (Test-MihomoOwnedProcessIdentity $Owner) -or
        -not (Test-MihomoLoopbackAddress $ExpectedLocalAddress)) {
        return $false
    }
    try {
        $Endpoints = @(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction Stop)
    }
    catch {
        return $false
    }
    if ($Endpoints.Count -eq 0) {
        return $false
    }
    foreach ($Endpoint in $Endpoints) {
        if ($Endpoint.OwningProcess -ne $Owner.Id -or
            -not (Test-MihomoAddressMatchesExpectedLoopback `
                ([string]$Endpoint.LocalAddress) $ExpectedLocalAddress)) {
            return $false
        }
    }
    return $true
}

function Stop-MihomoOwnedProcess {
    param([AllowNull()][psobject]$Owner)

    if ($null -eq $Owner -or $Owner.Stopped) {
        return $true
    }
    if (-not (Initialize-MihomoOwnedProcessIdentity $Owner)) {
        return $false
    }
    if ($Owner.Stopped) {
        return $true
    }
    if (-not (Test-MihomoOwnedProcessIdentity $Owner)) {
        try {
            $Owner.Process.Refresh()
            if ($Owner.Process.HasExited) {
                $Owner.Stopped = $true
                return $true
            }
        }
        catch {
            return $false
        }
        return $false
    }

    try {
        $Owner.Process.Kill()
        if (-not $Owner.Process.WaitForExit(5000)) {
            return $false
        }
    }
    catch {
        try {
            $Owner.Process.Refresh()
            if ($Owner.Process.HasExited) {
                $Owner.Stopped = $true
                return $true
            }
        }
        catch {
        }
        return $false
    }
    $Owner.Stopped = $true
    return $true
}

function Get-MihomoYamlMappingEntry {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$YamlLine)

    $Pattern = '^(?<indent>[ \t]*)(?<sequence>-[ \t]*)?(?:(?<plain>[A-Za-z0-9_][A-Za-z0-9_.-]*)|"(?<double>[^"]+)"|''(?<single>[^'']+)'')(?<beforeColon>[ \t]*):(?<tail>.*)$'
    $Match = [regex]::Match($YamlLine, $Pattern)
    if (-not $Match.Success) {
        return $null
    }
    $Key = if ($Match.Groups['plain'].Success) {
        $Match.Groups['plain'].Value
    }
    elseif ($Match.Groups['double'].Success) {
        $Match.Groups['double'].Value
    }
    else {
        $Match.Groups['single'].Value
    }
    return [pscustomobject]@{
        Key = $Key
        Value = $Match.Groups['tail'].Value
        Indent = $Match.Groups['indent'].Value.Length
        IsSequence = $Match.Groups['sequence'].Success
        IsQuoted = $Match.Groups['plain'].Success -eq $false
        HasValidColonSeparator = [string]::IsNullOrEmpty($Match.Groups['tail'].Value) -or
            [char]::IsWhiteSpace($Match.Groups['tail'].Value[0])
        RawKey = if ($Match.Groups['double'].Success) {
            $Match.Groups['double'].Value
        } elseif ($Match.Groups['single'].Success) {
            $Match.Groups['single'].Value
        } else { $Match.Groups['plain'].Value }
    }
}

function Get-MihomoYamlMappingEntries {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $Entry) {
            $Entry
        }
    }
}

function Test-MihomoYamlLineHasFlowSyntax {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line)

    $InSingleQuote = $false
    $InDoubleQuote = $false
    $Escaped = $false
    for ($Index = 0; $Index -lt $Line.Length; $Index++) {
        $Character = $Line[$Index]
        if ($InDoubleQuote) {
            if ($Escaped) {
                $Escaped = $false
            }
            elseif ($Character -eq '\') {
                $Escaped = $true
            }
            elseif ($Character -eq '"') {
                $InDoubleQuote = $false
            }
            continue
        }
        if ($InSingleQuote) {
            if ($Character -eq "'" -and $Index + 1 -lt $Line.Length -and $Line[$Index + 1] -eq "'") {
                $Index++
            }
            elseif ($Character -eq "'") {
                $InSingleQuote = $false
            }
            continue
        }
        if ($Character -eq '#' -and ($Index -eq 0 -or [char]::IsWhiteSpace($Line[$Index - 1]))) {
            break
        }
        if ($Character -eq '"') {
            $InDoubleQuote = $true
        }
        elseif ($Character -eq "'") {
            $InSingleQuote = $true
        }
        elseif ($Character -in @('{', '}', '[', ']')) {
            return $true
        }
        elseif ($Character -in @('&', '*', '!') -and
            ($Index -eq 0 -or [char]::IsWhiteSpace($Line[$Index - 1]) -or
                $Line[$Index - 1] -eq ':')) {
            throw 'Mihomo templates with YAML anchors, aliases, or tags are not supported'
        }
    }
    if ($InSingleQuote -or $InDoubleQuote) {
        throw 'Mihomo template contains an unsupported multiline or unterminated quoted scalar'
    }
    return $false
}

function Assert-MihomoYamlSupportedSyntax {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    $RootSeen = $false
    $DocumentStarted = $false
    $RootKeys = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Line in ($Yaml -split "`r?`n")) {
        if ($Line -match '^[ ]*\t') {
            throw 'Mihomo templates with tab indentation are not supported'
        }
        if (Test-MihomoYamlLineHasFlowSyntax $Line) {
            throw 'Mihomo templates with flow-style YAML are not supported by isolated cases'
        }
        $Trimmed = $Line.Trim()
        if ([string]::IsNullOrWhiteSpace($Trimmed) -or $Trimmed.StartsWith('#')) {
            continue
        }
        if ($Trimmed -eq '---') {
            if ($RootSeen -or $DocumentStarted) {
                throw 'Mihomo templates with multiple YAML documents are not supported'
            }
            $DocumentStarted = $true
            continue
        }
        if ($Trimmed -eq '...') {
            throw 'Mihomo templates with explicit YAML document endings are not supported'
        }
        $TrimmedStart = $Line.TrimStart()
        if ($TrimmedStart.StartsWith('?') -or $TrimmedStart.StartsWith('&') -or
            $TrimmedStart.StartsWith('*') -or $TrimmedStart.StartsWith('!') -or
            $TrimmedStart -match '^-[ \t]+\?') {
            throw 'Mihomo templates with explicit, anchored, or tagged YAML keys are not supported'
        }
        if ($TrimmedStart -match '^-[ \t]+["'']?[A-Za-z][A-Za-z0-9+.-]*://\S+') {
            continue
        }
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $Entry -and -not $Entry.HasValidColonSeparator) {
            throw 'Mihomo template contains an ambiguous YAML mapping separator'
        }
        if ($Entry -and $Entry.Value.Trim() -match '^[|>]') {
            throw 'Mihomo templates with YAML block scalars are not supported'
        }
        if (-not $RootSeen) {
            if ($null -eq $Entry -or $Entry.Indent -ne 0 -or $Entry.IsSequence) {
                throw 'Mihomo templates must use a block-style root mapping'
            }
            $RootSeen = $true
        }
        if ($Entry -and $Entry.IsQuoted -and
            ($Entry.RawKey.Contains('\') -or $Entry.RawKey.Contains("''"))) {
            throw 'Mihomo template contains an unsupported escaped mapping key'
        }
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            if (-not $RootKeys.Add($Entry.Key)) {
                throw 'Mihomo template contains a duplicate top-level YAML key'
            }
            continue
        }
        if ($null -eq $Entry -and $TrimmedStart -match '^-[ \t]+[|>]') {
            throw 'Mihomo templates with YAML block scalars are not supported'
        }
        if ($null -eq $Entry -and $TrimmedStart -match '^-[ \t]+\S') {
            continue
        }
        if ($null -eq $Entry) {
            throw 'Mihomo template contains an unsupported YAML mapping or scalar form'
        }
    }
    if (-not $RootSeen) {
        throw 'Mihomo template has no root mapping'
    }
}

function Remove-MihomoYamlComments {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Yaml)

    $OutputLines = [System.Collections.Generic.List[string]]::new()
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $InSingleQuote = $false
        $InDoubleQuote = $false
        $Escaped = $false
        for ($Index = 0; $Index -lt $Line.Length; $Index++) {
            $Character = $Line[$Index]
            if ($InDoubleQuote) {
                if ($Escaped) {
                    $Escaped = $false
                }
                elseif ($Character -eq '\') {
                    $Escaped = $true
                }
                elseif ($Character -eq '"') {
                    $InDoubleQuote = $false
                }
                continue
            }
            if ($InSingleQuote) {
                if ($Character -eq "'" -and $Index + 1 -lt $Line.Length -and
                    $Line[$Index + 1] -eq "'") {
                    $Index++
                }
                elseif ($Character -eq "'") {
                    $InSingleQuote = $false
                }
                continue
            }
            if ($Character -eq '"') {
                $InDoubleQuote = $true
            }
            elseif ($Character -eq "'") {
                $InSingleQuote = $true
            }
            elseif ($Character -eq '#' -and
                ($Index -eq 0 -or [char]::IsWhiteSpace($Line[$Index - 1]))) {
                break
            }
        }
        $Content = if ($Index -lt $Line.Length) { $Line.Substring(0, $Index) } else { $Line }
        if (-not [string]::IsNullOrWhiteSpace($Content)) {
            $OutputLines.Add($Content.TrimEnd())
        }
    }
    return $OutputLines -join "`n"
}

function Test-MihomoYamlContainsKey {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [switch]$TopLevelOnly
    )

    foreach ($Entry in (Get-MihomoYamlMappingEntries $Yaml)) {
        if (($TopLevelOnly -and ($Entry.Indent -ne 0 -or $Entry.IsSequence)) -or
            $Entry.Key -notin $Names) {
            continue
        }
        return $true
    }
    return $false
}

function Assert-MihomoNoShortcutInbounds {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    Assert-MihomoYamlSupportedSyntax $Yaml
    if (Test-MihomoYamlContainsKey $Yaml @('ss-config', 'vmess-config', 'tuic-server') -TopLevelOnly) {
        throw 'Isolated Mihomo templates cannot define shortcut inbound listeners'
    }
}

function Assert-MihomoNoDnsListener {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    Assert-MihomoYamlSupportedSyntax $Yaml
    foreach ($Line in (Get-MihomoYamlSection $Yaml 'dns')) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Key -eq 'listen') {
            throw 'Isolated Mihomo templates cannot define a DNS listen socket'
        }
    }
}

function Assert-MihomoRuleMode {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    Assert-MihomoYamlSupportedSyntax $Yaml
    $Modes = @(Get-MihomoYamlMappingEntries $Yaml | Where-Object {
            $_.Indent -eq 0 -and -not $_.IsSequence -and $_.Key -eq 'mode'
        })
    if ($Modes.Count -ne 1 -or
        (ConvertFrom-MihomoYamlScalar $Modes[0].Value) -ne 'rule') {
        throw 'Isolated Mihomo configuration must use rule mode'
    }
}

function Get-MihomoYamlSection {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$SectionName
    )

    $Lines = [System.Collections.Generic.List[string]]::new()
    $InSection = $false
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            if ($InSection) {
                break
            }
            $InSection = [string]::Equals($Entry.Key, $SectionName,
                [System.StringComparison]::OrdinalIgnoreCase)
            continue
        }
        if ($InSection) {
            $Lines.Add($Line)
        }
    }
    return $Lines.ToArray()
}

function Read-MihomoCasePrismConfiguration {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $JsonText = [System.IO.File]::ReadAllText($Path)
        $Configuration = ConvertFrom-Json -InputObject $JsonText -ErrorAction Stop
        if ($null -eq $Configuration -or -not ($Configuration -is [pscustomobject])) {
            throw 'Invalid Prism configuration shape'
        }
        return $Configuration
    }
    catch {
        throw 'Prism configuration template could not be read as a JSON object'
    }
}

function ConvertFrom-MihomoYamlScalar {
    param([Parameter(Mandatory = $true)][string]$Value)

    $Scalar = $Value.Trim()
    if ($Scalar.StartsWith('"')) {
        $Quoted = [regex]::Match($Scalar, '^"(?:\\.|[^"\\])*"(?:[ \t]+#.*)?$')
        if (-not $Quoted.Success) {
            throw 'Mihomo template contains an unsupported double-quoted scalar'
        }
        $JsonScalar = $Scalar -replace '(?:[ \t]+#.*)$', ''
        try {
            $Decoded = ConvertFrom-Json -InputObject $JsonScalar -ErrorAction Stop
        }
        catch {
            throw 'Mihomo template contains an invalid double-quoted scalar'
        }
        if (-not ($Decoded -is [string])) {
            throw 'Mihomo template contains a non-string double-quoted scalar'
        }
        return $Decoded
    }
    if ($Scalar.StartsWith("'")) {
        $Quoted = [regex]::Match($Scalar, "^'(?<value>(?:''|[^'])*)'(?:[ \t]+#.*)?$")
        if (-not $Quoted.Success) {
            throw 'Mihomo template contains an unsupported single-quoted scalar'
        }
        return $Quoted.Groups['value'].Value.Replace("''", "'")
    }
    if ($Scalar -match "^[^#]*[ \t]+#") {
        $Scalar = [regex]::Replace($Scalar, '[ \t]+#.*$', '').TrimEnd()
    }
    return $Scalar
}

function Assert-MihomoNamedOutboundListOrder {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][ValidateSet('proxies', 'proxy-groups')][string]$SectionName
    )

    foreach ($Line in (Get-MihomoYamlSection $Yaml $SectionName)) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.IsSequence -and $Entry.Indent -eq 2) {
            if ($Entry.Key -ne 'name' -or
                [string]::IsNullOrWhiteSpace((ConvertFrom-MihomoYamlScalar $Entry.Value))) {
                throw 'Mihomo outbound list entries must start with a non-empty name'
            }
            continue
        }
        if ($Entry -and $Entry.Indent -eq 2 -and -not $Entry.IsSequence) {
            throw 'Mihomo outbound lists must contain named mapping entries'
        }
        if ($Line -match '^(?<indent> *)-' -and $Matches['indent'].Length -lt 6) {
            throw 'Mihomo outbound list entry has an unsupported indentation or scalar form'
        }
    }
}

function Get-MihomoProxyEntries {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    Assert-MihomoNamedOutboundListOrder $Yaml 'proxies'
    $Entries = [System.Collections.Generic.List[object]]::new()
    $Current = $null
    foreach ($Line in (Get-MihomoYamlSection $Yaml 'proxies')) {
        $MappingEntry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $MappingEntry -and $MappingEntry.IsSequence -and
            $MappingEntry.Indent -eq 2 -and $MappingEntry.Key -eq 'name') {
            if ($null -ne $Current) {
                $Entries.Add($Current)
            }
            $Current = [pscustomobject]@{
                Name = ConvertFrom-MihomoYamlScalar $MappingEntry.Value.Trim()
                Type = ''
                SeenFields = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase)
            }
            [void]$Current.SeenFields.Add('name')
            continue
        }
        if ($null -ne $Current -and $null -ne $MappingEntry -and
            -not $MappingEntry.IsSequence -and $MappingEntry.Indent -eq 4) {
            if (-not $Current.SeenFields.Add($MappingEntry.Key)) {
                throw 'Mihomo proxy contains a duplicate YAML field'
            }
            if ($MappingEntry.Key -eq 'type') {
                $Current.Type = ConvertFrom-MihomoYamlScalar $MappingEntry.Value.Trim()
            }
        }
    }
    if ($null -ne $Current) {
        $Entries.Add($Current)
    }
    return $Entries.ToArray()
}

function Assert-MihomoProxyMatchesScenario {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName,
        [Parameter(Mandatory = $true)][string]$ExpectedProtocol
    )

    $ProtocolTypes = @{
        http = @('http')
        socks5 = @('socks5')
        vless = @('vless')
        trojan = @('trojan')
        vmess = @('vmess')
        shadowsocks = @('ss', 'shadowsocks')
        anytls = @('anytls')
        hysteria2 = @('hysteria2')
        tuic = @('tuic')
    }
    $Protocol = $ExpectedProtocol.ToLowerInvariant()
    if (-not $ProtocolTypes.ContainsKey($Protocol)) {
        throw 'Mihomo TCP case requires an explicit supported expected protocol'
    }
    $Selected = @(Get-MihomoProxyEntries $Yaml | Where-Object {
            [string]::Equals($_.Name, $ProxyName,
                [System.StringComparison]::OrdinalIgnoreCase)
        })
    if ($Selected.Count -ne 1 -or $Selected[0].Type -notin $ProtocolTypes[$Protocol]) {
        throw 'Selected Mihomo outbound type does not match the expected protocol scenario'
    }
}

function Assert-MihomoPrismProxyCredentials {
    param(
        [Parameter(Mandatory = $true)][psobject]$Configuration,
        [Parameter(Mandatory = $true)][string]$ExpectedProtocol,
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName
    )

    $Accounts = @($Configuration.Accounts)
    if ($Accounts.Count -ne 1 -or $null -eq $Accounts[0]) {
        throw 'Prism and Mihomo credential parity requires exactly one case account'
    }
    $CredentialSets = $Accounts[0].PSObject.Properties['Credentials']
    if ($null -eq $CredentialSets -or $CredentialSets.Value -isnot [pscustomobject]) {
        throw 'Prism case account does not expose protocol credential sets'
    }
    $Protocol = $ExpectedProtocol.ToLowerInvariant()
    $CredentialNames = @{
        http = 'Http'
        socks5 = 'Socks5'
        vless = 'Vless'
        trojan = 'Trojan'
        vmess = 'Vmess'
        shadowsocks = 'Shadowsocks2022'
        anytls = 'AnyTls'
        hysteria2 = 'hysteria2'
        tuic = 'Tuic'
    }
    if (-not $CredentialNames.ContainsKey($Protocol)) {
        throw 'Mihomo case has no account credential mapping for its protocol'
    }
    $Credential = $CredentialSets.Value.PSObject.Properties[$CredentialNames[$Protocol]]
    if ($null -eq $Credential -or $Credential.Value -isnot [string] -or
        [string]::IsNullOrEmpty($Credential.Value)) {
        throw 'Prism case account is missing the selected protocol credential'
    }
    if ($Protocol -in @('vless', 'vmess', 'tuic')) {
        $MihomoValue = Get-MihomoProxyScalar $Yaml $ProxyName 'uuid'
    }
    elseif ($Protocol -in @('http', 'socks5')) {
        $MihomoValue = Get-MihomoOptionalProxyScalar $Yaml $ProxyName 'password'
        if ($null -eq $MihomoValue) {
            $MihomoValue = Get-MihomoProxyScalar $Yaml $ProxyName 'username'
        }
    }
    else {
        $MihomoValue = Get-MihomoProxyScalar $Yaml $ProxyName 'password'
    }
    if (-not [string]::Equals($Credential.Value, $MihomoValue,
            [System.StringComparison]::Ordinal)) {
        throw 'Prism and Mihomo proxy credentials do not match'
    }
}

function Assert-MihomoPrismQuicCredential {
    param(
        [Parameter(Mandatory = $true)][psobject]$Configuration,
        [Parameter(Mandatory = $true)][string]$ExpectedProtocol,
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName
    )

    $Protocols = @($Configuration.Protocols | Where-Object {
            [string]::Equals([string]$_.Name, $ExpectedProtocol,
                [System.StringComparison]::OrdinalIgnoreCase) -and
            $null -ne $_.PSObject.Properties['Quic']
        })
    if ($Protocols.Count -ne 1) {
        throw 'Prism QUIC credential parity requires exactly one matching protocol'
    }
    $SecretReference = [string]$Protocols[0].Quic.CredentialSecretRef
    if ([string]::IsNullOrWhiteSpace($SecretReference)) {
        throw 'Prism QUIC protocol must reference a resolved credential secret'
    }
    $Secrets = $Configuration.PSObject.Properties['Secrets']
    if ($null -eq $Secrets -or $null -eq $Secrets.Value) {
        throw 'Prism QUIC configuration has no resolved secrets'
    }
    $SecretValue = $null
    if ($Secrets.Value -is [System.Collections.IDictionary]) {
        if ($Secrets.Value.Contains($SecretReference)) {
            $SecretValue = [string]$Secrets.Value[$SecretReference]
        }
    }
    else {
        $Secret = $Secrets.Value.PSObject.Properties[$SecretReference]
        if ($null -ne $Secret) {
            $SecretValue = [string]$Secret.Value
        }
    }
    $MihomoPassword = Get-MihomoProxyScalar $Yaml $ProxyName 'password'
    if ([string]::IsNullOrEmpty($SecretValue) -or
        -not [string]::Equals($SecretValue, $MihomoPassword,
            [System.StringComparison]::Ordinal)) {
        throw 'Prism QUIC secret reference and Mihomo password do not match'
    }
}

function Assert-MihomoPrismProxyServerName {
    param(
        [Parameter(Mandatory = $true)][psobject]$Configuration,
        [Parameter(Mandatory = $true)][string]$ExpectedProtocol,
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName,
        [AllowNull()][AllowEmptyString()][string]$MihomoServerName = $null
    )

    if ([string]::IsNullOrWhiteSpace($MihomoServerName)) {
        return
    }
    if ($ExpectedProtocol -in @('hysteria2', 'tuic')) {
        $QuicProtocol = @($Configuration.Protocols | Where-Object {
                [string]::Equals([string]$_.Name, $ExpectedProtocol,
                    [System.StringComparison]::OrdinalIgnoreCase) -and
                $null -ne $_.PSObject.Properties['Quic']
            })
        if ($QuicProtocol.Count -ne 1 -or
            -not [string]::Equals([string]$QuicProtocol[0].Quic.ServerName, $MihomoServerName,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Mihomo QUIC server-name does not match the Prism QUIC protocol'
        }
        return
    }
    $Protocols = @($Configuration.Protocols | Where-Object {
            [string]::Equals([string]$_.Name, $ExpectedProtocol,
                [System.StringComparison]::OrdinalIgnoreCase)
        })
    $Bindings = @($Configuration.ProtocolBindings | Where-Object {
            $Protocols.Id -contains $_.ProtocolId
        })
    $Matching = @($Bindings | Where-Object {
            $Recognition = $_.PSObject.Properties['Recognition']
            $null -ne $Recognition -and $null -ne $Recognition.Value -and
            $null -ne $Recognition.Value.PSObject.Properties['Pattern'] -and
            [string]::Equals([string]$Recognition.Value.Pattern, $MihomoServerName,
                [System.StringComparison]::OrdinalIgnoreCase)
        })
    if ($Matching.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace([string]$Matching[0].CarrierId)) {
        throw 'Mihomo server-name does not identify one Prism carrier binding'
    }
}

function Get-MihomoYamlUniqueTopLevelScalar {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Name
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $SectionEntries = @(Get-MihomoYamlMappingEntries $Yaml | Where-Object {
            $_.Indent -eq 0 -and -not $_.IsSequence -and $_.Key -eq $Section
        })
    if ($SectionEntries.Count -gt 1) {
        throw 'Mihomo top-level scalar section is repeated'
    }
    $Values = [System.Collections.Generic.List[string]]::new()
    foreach ($Line in (Get-MihomoYamlSection $Yaml $Section)) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $Entry -and -not $Entry.IsSequence -and
            $Entry.Indent -eq 2 -and $Entry.Key -eq $Name) {
            $Values.Add((ConvertFrom-MihomoYamlScalar $Entry.Value))
        }
    }
    if ($Values.Count -gt 1) {
        throw 'Mihomo top-level scalar value is repeated'
    }
    return if ($Values.Count -eq 1) { $Values[0] } else { $null }
}

function Assert-MihomoProxyTypeSupported {
    param([Parameter(Mandatory = $true)][psobject]$Proxy)

    $SupportedTypes = @(
        'http', 'socks5', 'vless', 'trojan', 'vmess', 'ss', 'shadowsocks',
        'anytls', 'hysteria2', 'tuic')
    if ($Proxy.Type -notin $SupportedTypes) {
        throw 'Isolated Mihomo route uses an unsupported outbound type'
    }
    if ($Proxy.SeenFields.Contains('peers')) {
        throw 'Isolated Mihomo outbounds cannot define nested peer endpoints'
    }
    if ($Proxy.Type -in @('ss', 'shadowsocks') -and
        ($Proxy.SeenFields.Contains('plugin') -or $Proxy.SeenFields.Contains('plugin-opts'))) {
        throw 'Isolated Shadowsocks outbounds cannot launch plugin endpoints'
    }
}

function Get-MihomoProxyGroupEntries {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    Assert-MihomoNamedOutboundListOrder $Yaml 'proxy-groups'
    $Entries = [System.Collections.Generic.List[object]]::new()
    $Current = $null
    $ReadMembers = $false
    foreach ($Line in (Get-MihomoYamlSection $Yaml 'proxy-groups')) {
        $MappingEntry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $MappingEntry -and $MappingEntry.IsSequence -and
            $MappingEntry.Indent -eq 2 -and $MappingEntry.Key -eq 'name') {
            if ($null -ne $Current) {
                $Entries.Add($Current)
            }
            $Current = [pscustomobject]@{
                Name = ConvertFrom-MihomoYamlScalar $MappingEntry.Value.Trim()
                Type = ''
                Members = [System.Collections.Generic.List[string]]::new()
                DynamicMembers = $false
                SeenFields = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase)
            }
            [void]$Current.SeenFields.Add('name')
            $ReadMembers = $false
            continue
        }
        if ($null -eq $Current) {
            continue
        }
        if ($null -ne $MappingEntry -and -not $MappingEntry.IsSequence -and
            $MappingEntry.Indent -eq 4) {
            if (-not $Current.SeenFields.Add($MappingEntry.Key)) {
                $Current.DynamicMembers = $true
            }
            if ($MappingEntry.Key -eq 'type') {
                $Current.Type = ConvertFrom-MihomoYamlScalar $MappingEntry.Value.Trim()
                $ReadMembers = $false
                continue
            }
            if ($MappingEntry.Key -eq 'proxies') {
                if (-not [string]::IsNullOrWhiteSpace($MappingEntry.Value)) {
                    $Current.DynamicMembers = $true
                }
                $ReadMembers = [string]::IsNullOrWhiteSpace($MappingEntry.Value)
                continue
            }
            if ($MappingEntry.Key -match '^(?i:include|exclude|filter|use)' -or
                $MappingEntry.Key -notin @('hidden', 'icon')) {
                $Current.DynamicMembers = $true
            }
            $ReadMembers = $false
            continue
        }
        if ($ReadMembers -and $Line -match '^\s{6}-\s*(?<member>[^#]+?)\s*$') {
            $Current.Members.Add((ConvertFrom-MihomoYamlScalar $Matches['member']))
            continue
        }
        if ($Line -match '^\s{4}\S') {
            $ReadMembers = $false
        }
    }
    if ($null -ne $Current) {
        $Entries.Add($Current)
    }
    return $Entries.ToArray()
}

function Assert-MihomoNoProbeGroups {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    Assert-MihomoYamlSupportedSyntax $Yaml
    foreach ($Group in (Get-MihomoProxyGroupEntries $Yaml)) {
        if ($Group.Type -in @('url-test', 'fallback', 'load-balance') -or
            $Group.DynamicMembers) {
            throw 'Isolated Mihomo templates cannot use probe or dynamic proxy-group settings'
        }
    }
}

function Get-MihomoMatchTargets {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    $Targets = [System.Collections.Generic.List[string]]::new()
    foreach ($Line in (Get-MihomoYamlSection $Yaml 'rules')) {
        if ($Line -match '^\s{2}-\s*MATCH,(?<target>[^,]+?)\s*$') {
            $Targets.Add((ConvertFrom-MihomoYamlScalar $Matches['target']))
        }
    }
    return $Targets.ToArray()
}

function Assert-MihomoRouteTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ExpectedTarget,
        [switch]$AllowPlaceholder
    )

    $MatchTargets = @(Get-MihomoMatchTargets $Yaml)
    if ($MatchTargets.Count -ne 1 -or $MatchTargets[0] -ne $ExpectedTarget) {
        throw 'Mihomo template must contain one MATCH route to the selected target'
    }
    if ($AllowPlaceholder -and $ExpectedTarget -eq 'PrismPreview-Active') {
        return
    }
    $Groups = @(Get-MihomoProxyGroupEntries $Yaml | Where-Object { $_.Name -eq $ExpectedTarget })
    $Proxies = @(Get-MihomoProxyEntries $Yaml | Where-Object { $_.Name -eq $ExpectedTarget })
    if (($Groups.Count + $Proxies.Count) -ne 1) {
        throw 'Mihomo MATCH route target must name exactly one declared proxy or proxy group'
    }
}

function Assert-MihomoQuicRoute {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][ValidateSet('hysteria2', 'tuic')][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$ExpectedGroup,
        [Parameter(Mandatory = $true)][string]$ExpectedRoute,
        [switch]$AllowPlaceholder
    )

    $AllProxies = @(Get-MihomoProxyEntries $Yaml)
    $AllGroups = @(Get-MihomoProxyGroupEntries $Yaml)
    $ProxyNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Proxy in $AllProxies) {
        if (-not $ProxyNames.Add($Proxy.Name)) {
            throw 'QUIC template contains a duplicate proxy name'
        }
    }
    $GroupNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Group in $AllGroups) {
        if (-not $GroupNames.Add($Group.Name) -or $ProxyNames.Contains($Group.Name)) {
            throw 'QUIC template contains an ambiguous proxy group name'
        }
    }
    $ProxyEntries = @($AllProxies | Where-Object { $_.Type -eq $Protocol })
    if ($ProxyEntries.Count -ne 1) {
        throw "QUIC template must declare exactly one $Protocol proxy outbound"
    }
    $ProxyName = $ProxyEntries[0].Name
    Assert-MihomoQuicProxyEgressFields $Yaml $Protocol $ProxyName
    $Groups = @($AllGroups | Where-Object { $_.Name -eq $ExpectedGroup })
    if ($Groups.Count -ne 1 -or $Groups[0].Type -ne 'select' -or
        $Groups[0].DynamicMembers -or $Groups[0].Members.Count -ne 1 -or
        -not [string]::Equals($ProxyName, $Groups[0].Members[0],
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "QUIC proxy group must select only its $Protocol outbound"
    }
    $RuleLines = @(Get-MihomoYamlSection $Yaml 'rules' |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -notmatch '^\s*#' })
    if ($RuleLines.Count -ne 1 -or
        $RuleLines[0] -notmatch '^\s{2}-\s*MATCH,\s*[^,]+?\s*$') {
        throw 'QUIC template must contain only its single effective MATCH route'
    }
    $MatchTargets = @(Get-MihomoMatchTargets $Yaml)
    if ($MatchTargets.Count -ne 1 -or $MatchTargets[0] -ne $ExpectedRoute) {
        throw "QUIC template must route its single MATCH rule to $ExpectedRoute"
    }
    if ($AllowPlaceholder -and $ExpectedRoute -eq 'PrismPreview-Active') {
        $PlaceholderGroups = @($AllGroups | Where-Object {
                $_.Members -contains $ProxyName -or
                [string]::Equals($_.Name, $ExpectedGroup,
                    [System.StringComparison]::OrdinalIgnoreCase)
            })
        if ($PlaceholderGroups.Count -lt 1) {
            throw 'QUIC template placeholder does not reference its protocol group'
        }
    }
    return $ProxyName
}

function Assert-MihomoQuicProxyEgressFields {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][ValidateSet('hysteria2', 'tuic')][string]$Protocol,
        [Parameter(Mandatory = $true)][string]$ProxyName
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $Section = ''
    $CurrentProxy = ''
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $Section = $Entry.Key
            $CurrentProxy = ''
            continue
        }
        if ($Section -ne 'proxies' -or $null -eq $Entry) {
            continue
        }
        if ($Entry.IsSequence -and $Entry.Indent -eq 2 -and $Entry.Key -eq 'name') {
            $CurrentProxy = ConvertFrom-MihomoYamlScalar $Entry.Value
            continue
        }
        if ($CurrentProxy -ne $ProxyName -or $Entry.IsSequence -or $Entry.Indent -ne 4) {
            continue
        }
        if ($Protocol -eq 'tuic' -and $Entry.Key -eq 'ip' -and
            -not [string]::IsNullOrWhiteSpace((ConvertFrom-MihomoYamlScalar $Entry.Value))) {
            throw 'Isolated TUIC outbound cannot override its loopback server address with ip'
        }
        if ($Protocol -eq 'tuic' -and $Entry.Key -eq 'disable-sni') {
            $DisableSni = $false
            if (-not [bool]::TryParse((ConvertFrom-MihomoYamlScalar $Entry.Value),
                    [ref]$DisableSni) -or $DisableSni) {
                throw 'Isolated TUIC outbound must not disable server-name indication'
            }
        }
        if ($Protocol -eq 'hysteria2' -and $Entry.Key -in @('ports', 'realm-opts')) {
            throw 'Isolated Hysteria2 outbound cannot enable port hopping or Realm/STUN networking'
        }
    }
}

function Get-MihomoQuicProxyAlpn {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $Values = [System.Collections.Generic.List[string]]::new()
    $CurrentProxy = ''
    $SelectedProxy = $false
    $FoundAlpn = $false
    $ReadingAlpn = $false
    foreach ($Line in (Get-MihomoYamlSection $Yaml 'proxies')) {
        if ([string]::IsNullOrWhiteSpace($Line) -or $Line.TrimStart().StartsWith('#')) {
            continue
        }
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.IsSequence -and $Entry.Indent -eq 2) {
            $CurrentProxy = if ($Entry.Key -eq 'name') {
                ConvertFrom-MihomoYamlScalar $Entry.Value.Trim()
            } else { '' }
            $SelectedProxy = [string]::Equals(
                $CurrentProxy, $ProxyName, [System.StringComparison]::OrdinalIgnoreCase)
            $ReadingAlpn = $false
            continue
        }
        if (-not $SelectedProxy) {
            continue
        }
        if ($Entry -and -not $Entry.IsSequence -and $Entry.Indent -eq 4) {
            if ($Entry.Key -eq 'alpn') {
                if ($FoundAlpn) {
                    throw 'Selected QUIC outbound contains duplicate ALPN fields'
                }
                $FoundAlpn = $true
                if (-not [string]::IsNullOrWhiteSpace($Entry.Value)) {
                    throw 'Selected QUIC outbound ALPN must be a block-style YAML string list'
                }
                $ReadingAlpn = $true
            } else {
                $ReadingAlpn = $false
            }
            continue
        }
        if ($ReadingAlpn -and $Line -match '^ {6}-[ \t]+(?<value>\S.*)$') {
            $Values.Add((ConvertFrom-MihomoYamlScalar $Matches['value']))
            continue
        }
        if ($ReadingAlpn) {
            throw 'Selected QUIC outbound ALPN contains an unsupported YAML list item'
        }
    }
    return $Values.ToArray()
}

function Assert-MihomoQuicProxyAlpn {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName,
        [Parameter(Mandatory = $true)][string]$ExpectedAlpn
    )

    if ($ExpectedAlpn -cne 'h3') {
        throw 'Prism QUIC runner requires the configured ALPN to be exactly h3'
    }
    $Values = @(Get-MihomoQuicProxyAlpn $Yaml $ProxyName)
    if ($Values.Count -ne 1 -or $Values[0] -cne $ExpectedAlpn) {
        throw 'Mihomo QUIC outbound ALPN must exactly match Prism Quic.Alpn=h3'
    }
}

function New-MihomoControllerSecret {
    $Bytes = [byte[]]::new(32)
    $Random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Random.GetBytes($Bytes)
        return [Convert]::ToHexString($Bytes).ToLowerInvariant()
    }
    finally {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($Bytes)
        $Random.Dispose()
    }
}

function Get-MihomoConnectionsSnapshot {
    param(
        [Parameter(Mandatory = $true)][int]$ControllerPort,
        [Parameter(Mandatory = $true)][string]$ControllerSecret,
        [Parameter(Mandatory = $true)][psobject]$MihomoOwner
    )

    if (-not (Test-MihomoOwnedProcessIdentity $MihomoOwner)) {
        throw 'The owned Mihomo process identity is unavailable before controller access'
    }
    if (-not (Test-MihomoOwnedTcpPort $MihomoOwner $ControllerPort '127.0.0.1')) {
        throw 'The loopback controller listener is not owned by this Mihomo process'
    }
    if (-not (Test-MihomoOwnedProcessIdentity $MihomoOwner)) {
        throw 'The owned Mihomo process identity changed before controller access'
    }
    return Invoke-MihomoControllerJson `
        $MihomoOwner $ControllerPort $ControllerSecret '/connections'
}

function Get-MihomoControllerProxiesSnapshot {
    param(
        [Parameter(Mandatory = $true)][int]$ControllerPort,
        [Parameter(Mandatory = $true)][string]$ControllerSecret,
        [Parameter(Mandatory = $true)][psobject]$MihomoOwner
    )

    $Snapshot = Invoke-MihomoControllerJson `
        $MihomoOwner $ControllerPort $ControllerSecret '/proxies'
    $ProxiesProperty = $Snapshot.PSObject.Properties['proxies']
    if ($null -eq $ProxiesProperty -or $null -eq $ProxiesProperty.Value -or
        $ProxiesProperty.Value -isnot [pscustomobject]) {
        throw 'Mihomo proxies API returned an invalid snapshot'
    }
    return $Snapshot
}

function Get-MihomoSelectedProxyChainSnapshot {
    param(
        [Parameter(Mandatory = $true)][int]$ControllerPort,
        [Parameter(Mandatory = $true)][string]$ControllerSecret,
        [Parameter(Mandatory = $true)][psobject]$MihomoOwner,
        [Parameter(Mandatory = $true)][string[]]$ExpectedChain
    )

    $Snapshot = Get-MihomoControllerProxiesSnapshot `
        $ControllerPort $ControllerSecret $MihomoOwner
    Assert-MihomoSelectedProxySnapshot `
        $Snapshot $ExpectedChain[-1] $ExpectedChain[0] $ExpectedChain
    return $Snapshot
}

function Invoke-MihomoControllerJson {
    param(
        [Parameter(Mandatory = $true)][psobject]$MihomoOwner,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ControllerPort,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$ControllerSecret,
        [Parameter(Mandatory = $true)][ValidateSet('/proxies', '/connections')][string]$Path
    )

    if (-not (Test-MihomoOwnedProcessIdentity $MihomoOwner)) {
        throw 'The owned Mihomo process identity is unavailable before controller access'
    }
    if (-not (Test-MihomoOwnedTcpPort $MihomoOwner $ControllerPort '127.0.0.1')) {
        throw 'The loopback controller listener is not owned by this Mihomo process'
    }
    $Uri = "http://127.0.0.1:$ControllerPort$Path"
    $Handler = [System.Net.Http.HttpClientHandler]::new()
    $Handler.UseProxy = $false
    $Handler.AllowAutoRedirect = $false
    $Client = [System.Net.Http.HttpClient]::new($Handler)
    $Client.Timeout = [TimeSpan]::FromSeconds(1)
    $Request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::Get, $Uri)
    $Response = $null
    try {
        if (-not (Test-MihomoOwnedTcpPort $MihomoOwner $ControllerPort '127.0.0.1') -or
            -not (Test-MihomoOwnedProcessIdentity $MihomoOwner)) {
            throw 'The loopback controller listener changed before request authorization'
        }
        $Request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new(
            'Bearer', $ControllerSecret)
        $Response = $Client.SendAsync($Request).GetAwaiter().GetResult()
        if (-not $Response.IsSuccessStatusCode) {
            throw "Mihomo controller API returned a non-success response for $Path"
        }
        $Body = $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        try {
            $Snapshot = ConvertFrom-Json -InputObject $Body -ErrorAction Stop
        }
        catch {
            throw "Mihomo controller API returned invalid JSON for $Path"
        }
        return $Snapshot
    }
    finally {
        if ($null -ne $Response) {
            $Response.Dispose()
        }
        $Request.Dispose()
        $Client.Dispose()
    }
}

function Assert-MihomoSelectedProxySnapshot {
    param(
        [Parameter(Mandatory = $true)][psobject]$Snapshot,
        [Parameter(Mandatory = $true)][string]$ExpectedRoute,
        [Parameter(Mandatory = $true)][string]$ExpectedLeaf,
        [Parameter(Mandatory = $true)][string[]]$ExpectedChain
    )

    $Proxies = $Snapshot.proxies
    $Route = $Proxies.PSObject.Properties[$ExpectedRoute]
    $Leaf = $Proxies.PSObject.Properties[$ExpectedLeaf]
    if ($null -eq $Route -or $null -eq $Leaf) {
        throw 'Mihomo proxies API is missing the selected route or leaf'
    }
    if ($Leaf.Value.type -eq 'Selector' -or $Leaf.Value.type -eq 'URLTest' -or
        $Leaf.Value.type -eq 'Fallback' -or $Leaf.Value.type -eq 'LoadBalance') {
        throw 'Mihomo selected leaf is a group instead of a concrete outbound'
    }
    if ($ExpectedChain.Count -eq 1) {
        if (-not [string]::Equals($ExpectedRoute, $ExpectedLeaf,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Direct Mihomo proxy route does not identify its leaf proxy'
        }
        return
    }
    if ($Route.Value.type -ne 'Selector' -or
        -not [string]::Equals([string]$Route.Value.now, $ExpectedLeaf,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mihomo selected route does not select the expected leaf proxy'
    }

    $Groups = @()
    for ($Index = 0; $Index -lt $ExpectedChain.Count - 1; $Index++) {
        $GroupProperty = $Proxies.PSObject.Properties[$ExpectedChain[$Index + 1]]
        if ($null -eq $GroupProperty -or
            $GroupProperty.Value.type -ne 'Selector' -or
            -not [string]::Equals([string]$GroupProperty.Value.now, $ExpectedChain[$Index],
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Mihomo proxy chain selection differs from the expected route chain'
        }
        $Groups += $GroupProperty
    }
}

function Assert-MihomoConnectionsSnapshotShape {
    param([Parameter(Mandatory = $true)][psobject]$Snapshot)

    $ConnectionsProperty = $Snapshot.PSObject.Properties['connections']
    if ($null -eq $ConnectionsProperty -or
        $ConnectionsProperty.Value -isnot [System.Array]) {
        throw 'Mihomo connections API returned an invalid snapshot'
    }
    foreach ($Connection in $ConnectionsProperty.Value) {
        if ($null -eq $Connection -or $Connection -isnot [pscustomobject]) {
            throw 'Mihomo connections API returned a non-object connection entry'
        }
    }
}

function Get-MihomoExpectedRouteChain {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ExpectedRoute
    )

    $Groups = @{}
    foreach ($Group in (Get-MihomoProxyGroupEntries $Yaml)) {
        if ($Groups.ContainsKey($Group.Name)) {
            throw 'Mihomo route chain contains a duplicate group name'
        }
        $Groups[$Group.Name] = $Group
    }
    $Proxies = @{}
    foreach ($Proxy in (Get-MihomoProxyEntries $Yaml)) {
        if ($Proxies.ContainsKey($Proxy.Name)) {
            throw 'Mihomo route chain contains a duplicate proxy name'
        }
        $Proxies[$Proxy.Name] = $Proxy.Type
    }
    foreach ($GroupName in $Groups.Keys) {
        if ($Proxies.ContainsKey($GroupName)) {
            throw 'Mihomo route chain contains an ambiguous proxy and group name'
        }
    }
    $Visited = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $RouteToLeaf = [System.Collections.Generic.List[string]]::new()
    $Current = $ExpectedRoute
    while ($true) {
        if (-not $Visited.Add($Current)) {
            throw 'Mihomo route chain contains a cycle'
        }
        if ($Groups.ContainsKey($Current)) {
            $Members = @($Groups[$Current].Members)
            if ($Groups[$Current].DynamicMembers -or $Members.Count -ne 1) {
                throw 'Mihomo route evidence requires single-member groups'
            }
            [void]$RouteToLeaf.Add($Current)
            $Current = [string]$Members[0]
            continue
        }
        if (-not $Proxies.ContainsKey($Current) -or
            $Proxies[$Current] -in @('DIRECT', 'REJECT', 'PASS', 'COMPATIBLE')) {
            throw 'Mihomo route evidence requires one declared proxy leaf'
        }
        [void]$RouteToLeaf.Add($Current)
        break
    }
    $ExpectedChain = [string[]]$RouteToLeaf.ToArray()
    [Array]::Reverse($ExpectedChain)
    return $ExpectedChain
}

function Set-MihomoIsolatedRouteClosure {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ExpectedRoute
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    if ($ExpectedRoute -notmatch '^[A-Za-z0-9_. -]+$') {
        throw 'Isolated Mihomo route names must use a plain safe scalar'
    }
    Assert-MihomoRouteTarget $Yaml $ExpectedRoute
    $Chain = @(Get-MihomoExpectedRouteChain $Yaml $ExpectedRoute)
    $Groups = @(Get-MihomoProxyGroupEntries $Yaml)
    $Proxies = @(Get-MihomoProxyEntries $Yaml)
    $GroupNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Group in $Groups) {
        [void]$GroupNames.Add($Group.Name)
    }
    $ProxyNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Proxy in $Proxies) {
        [void]$ProxyNames.Add($Proxy.Name)
    }
    $AllowedGroups = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $AllowedProxy = [string]$Chain[0]
    for ($Index = 0; $Index -lt $Chain.Count; $Index++) {
        if ($Chain[$Index] -notmatch '^[A-Za-z0-9_. -]+$') {
            throw 'Isolated Mihomo route names must use a plain safe scalar'
        }
        if ($GroupNames.Contains($Chain[$Index])) {
            if ($Groups | Where-Object {
                    $_.Name -eq $Chain[$Index] -and $_.Type -ne 'select'
                }) {
                throw 'Isolated Mihomo route closure only supports select proxy groups'
            }
            [void]$AllowedGroups.Add($Chain[$Index])
            continue
        }
        if ($Chain[$Index] -ne $AllowedProxy -or -not $ProxyNames.Contains($Chain[$Index])) {
            throw 'Isolated Mihomo route closure must terminate at exactly one declared proxy'
        }
    }
    if ($AllowedGroups.Count -ne $Groups.Count -and $Groups.Count -eq 0) {
        throw 'Isolated Mihomo route closure has no proxy group section'
    }

    $Lines = [System.Collections.Generic.List[string]]::new()
    $Section = ''
    $KeepObject = $true
    $SawRules = $false
    $SawProxies = $false
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $Section = $Entry.Key
            $KeepObject = $true
            if ($Section -eq 'rules') {
                if (-not [string]::IsNullOrWhiteSpace($Entry.Value)) {
                    throw 'Isolated Mihomo rules must use a block list'
                }
                $Lines.Add('rules:')
                $Lines.Add("  - MATCH,$ExpectedRoute")
                $SawRules = $true
                $KeepObject = $false
                continue
            }
            if ($Section -eq 'proxies') {
                if (-not [string]::IsNullOrWhiteSpace($Entry.Value)) {
                    throw 'Isolated Mihomo proxies must use a block list'
                }
                $SawProxies = $true
            }
            if ($Section -eq 'proxy-groups' -and
                -not [string]::IsNullOrWhiteSpace($Entry.Value)) {
                throw 'Isolated Mihomo proxy groups must use a block list'
            }
            $Lines.Add($Line)
            continue
        }
        if ($Section -eq 'rules') {
            continue
        }
        if ($Section -in @('proxies', 'proxy-groups')) {
            if ($Entry -and $Entry.IsSequence -and $Entry.Indent -eq 2) {
                if ($Entry.Key -ne 'name') {
                    throw 'Isolated Mihomo outbound entries must begin with a name field'
                }
                $Name = ConvertFrom-MihomoYamlScalar $Entry.Value
                $KeepObject = if ($Section -eq 'proxies') {
                    [string]::Equals($Name, $AllowedProxy,
                        [System.StringComparison]::OrdinalIgnoreCase)
                }
                else {
                    $AllowedGroups.Contains($Name)
                }
            }
            if ($KeepObject) {
                $Lines.Add($Line)
            }
            continue
        }
        $Lines.Add($Line)
    }
    if (-not $SawRules -or -not $SawProxies) {
        throw 'Isolated Mihomo route closure requires rules and proxy sections'
    }
    $ClosedYaml = $Lines -join "`n"
    Assert-MihomoRouteTarget $ClosedYaml $ExpectedRoute
    $ClosedChain = @(Get-MihomoExpectedRouteChain $ClosedYaml $ExpectedRoute)
    if ($ClosedChain.Count -ne $Chain.Count -or
        @(Get-MihomoProxyEntries $ClosedYaml).Count -ne 1 -or
        @(Get-MihomoProxyGroupEntries $ClosedYaml).Count -ne $AllowedGroups.Count) {
        throw 'Isolated Mihomo route closure retained an unreachable outbound object'
    }
    for ($Index = 0; $Index -lt $Chain.Count; $Index++) {
        if (-not [string]::Equals($Chain[$Index], $ClosedChain[$Index],
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'Isolated Mihomo route closure changed the selected proxy chain'
        }
    }
    return $ClosedYaml
}

function Assert-MihomoIsolatedRouteClosure {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ExpectedRoute,
        [Parameter(Mandatory = $true)][string]$ExpectedProxy,
        [Parameter(Mandatory = $true)][string]$ExpectedServer,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ExpectedPort
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    Assert-MihomoRouteTarget $Yaml $ExpectedRoute
    $Rules = @(Get-MihomoYamlSection $Yaml 'rules' |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $MatchTargets = @(Get-MihomoMatchTargets $Yaml)
    if ($Rules.Count -ne 1 -or $MatchTargets.Count -ne 1) {
        throw 'Isolated Mihomo routing must contain only its single MATCH rule'
    }
    $Chain = @(Get-MihomoExpectedRouteChain $Yaml $ExpectedRoute)
    $Proxies = @(Get-MihomoProxyEntries $Yaml)
    $Groups = @(Get-MihomoProxyGroupEntries $Yaml)
    if ($Chain.Count -lt 1 -or
        -not [string]::Equals($Chain[0], $ExpectedProxy,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $Proxies.Count -ne 1 -or
        -not [string]::Equals($Proxies[0].Name, $ExpectedProxy,
            [System.StringComparison]::OrdinalIgnoreCase) -or
        $Groups.Count -ne ($Chain.Count - 1)) {
        throw 'Isolated Mihomo routing must retain only the selected proxy chain'
    }
    Assert-MihomoProxyTypeSupported $Proxies[0]
    foreach ($Group in $Groups) {
        if ($Group.Type -ne 'select' -or $Group.DynamicMembers -or
            $Group.Members.Count -ne 1) {
            throw 'Isolated Mihomo route groups must remain explicit singleton selects'
        }
    }
    foreach ($Field in @('dialer-proxy', 'detour', 'interface-name', 'routing-mark')) {
        if ($Proxies[0].SeenFields.Contains($Field)) {
            throw 'Selected Mihomo outbound cannot delegate or override its loopback route'
        }
    }
    if ($Proxies[0].Type -in @('hysteria2', 'tuic')) {
        Assert-MihomoQuicProxyEgressFields $Yaml $Proxies[0].Type $ExpectedProxy
    }

    $ActualServer = Get-MihomoProxyScalar $Yaml $ExpectedProxy 'server'
    $ActualPort = Get-MihomoProxyScalar $Yaml $ExpectedProxy 'port'
    $ServerAddress = $null
    $ExpectedAddress = $null
    $Port = 0
    if (-not [System.Net.IPAddress]::TryParse($ActualServer, [ref]$ServerAddress) -or
        -not [System.Net.IPAddress]::TryParse($ExpectedServer, [ref]$ExpectedAddress) -or
        -not (Test-MihomoLoopbackAddress $ActualServer) -or
        -not $ServerAddress.Equals($ExpectedAddress) -or
        -not [int]::TryParse($ActualPort, [ref]$Port) -or $Port -ne $ExpectedPort) {
        throw 'Selected Mihomo outbound must target the requested loopback Prism listener'
    }
}

function Get-MihomoConnectionRouteEvidence {
    param(
        [Parameter(Mandatory = $true)][psobject]$Connection,
        [Parameter(Mandatory = $true)][string]$TargetAddress,
        [Parameter(Mandatory = $true)][int]$TargetPort,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ExpectedInboundPort,
        [Parameter(Mandatory = $true)][ValidateSet('tcp', 'udp')][string]$Network,
        [Parameter(Mandatory = $true)][string]$ExpectedRoute,
        [Parameter(Mandatory = $true)][string[]]$ExpectedChain
    )

    $Metadata = $Connection.PSObject.Properties['metadata']
    if ($null -eq $Metadata) {
        return $null
    }
    $DestinationIp = $Metadata.Value.PSObject.Properties['destinationIP']
    $DestinationPort = $Metadata.Value.PSObject.Properties['destinationPort']
    $ActualNetwork = $Metadata.Value.PSObject.Properties['network']
    $InboundPort = $Metadata.Value.PSObject.Properties['inboundPort']
    if ($null -eq $DestinationIp -or $null -eq $DestinationPort -or
        $null -eq $ActualNetwork -or $null -eq $InboundPort) {
        return $null
    }

    $ActualAddress = $null
    $ExpectedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse([string]$DestinationIp.Value, [ref]$ActualAddress) -or
        -not [System.Net.IPAddress]::TryParse($TargetAddress, [ref]$ExpectedAddress)) {
        return $null
    }
    if ($ActualAddress.IsIPv4MappedToIPv6) {
        $ActualAddress = $ActualAddress.MapToIPv4()
    }
    $ActualPort = 0
    $ActualInboundPort = 0
    if (-not [int]::TryParse([string]$DestinationPort.Value, [ref]$ActualPort) -or
        -not [int]::TryParse([string]$InboundPort.Value, [ref]$ActualInboundPort) -or
        -not $ActualAddress.Equals($ExpectedAddress) -or
        $ActualPort -ne $TargetPort -or
        $ActualInboundPort -ne $ExpectedInboundPort -or
        -not [string]::Equals([string]$ActualNetwork.Value, $Network,
            [System.StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }

    $Rule = $Connection.PSObject.Properties['rule']
    $RulePayload = $Connection.PSObject.Properties['rulePayload']
    if ($null -eq $Rule -or $null -eq $RulePayload -or
        $Rule.Value -isnot [string] -or $RulePayload.Value -isnot [string] -or
        -not [string]::Equals([string]$Rule.Value, 'Match',
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::IsNullOrWhiteSpace([string]$RulePayload.Value)) {
        return $null
    }

    $ChainsProperty = $Connection.PSObject.Properties['chains']
    if ($null -eq $ChainsProperty -or $ChainsProperty.Value -isnot [System.Array]) {
        return $null
    }
    $Chains = [System.Collections.Generic.List[string]]::new()
    foreach ($Chain in $ChainsProperty.Value) {
        if ($Chain -isnot [string] -or [string]::IsNullOrWhiteSpace($Chain)) {
            return $null
        }
        $Chains.Add($Chain)
    }
    if ($Chains.Count -eq 1 -and $Chains[0] -eq 'DIRECT') {
        if ($ExpectedChain.Count -ne 0) {
            return $null
        }
    }
    elseif ($Chains.Count -ne $ExpectedChain.Count) {
        return $null
    }
    for ($Index = 0; $Index -lt $ExpectedChain.Count; $Index++) {
        if (-not [string]::Equals($Chains[$Index], $ExpectedChain[$Index],
                [System.StringComparison]::OrdinalIgnoreCase)) {
            return $null
        }
    }
    return [pscustomobject]@{
        DestinationAddress = $ActualAddress.ToString()
        DestinationPort = $ActualPort
        InboundPort = $ActualInboundPort
        Network = ([string]$ActualNetwork.Value).ToLowerInvariant()
        Rule = [string]$Rule.Value
        RulePayload = [string]$RulePayload.Value
        ExpectedRoute = $ExpectedRoute
        Chains = $Chains.ToArray()
    }
}

function Wait-MihomoRouteEvidence {
    param(
        [Parameter(Mandatory = $true)][System.Diagnostics.Process[]]$RequestProcesses,
        [Parameter(Mandatory = $true)][psobject]$MihomoOwner,
        [Parameter(Mandatory = $true)][int]$ControllerPort,
        [Parameter(Mandatory = $true)][string]$ControllerSecret,
        [Parameter(Mandatory = $true)][string]$TargetAddress,
        [Parameter(Mandatory = $true)][int]$TargetPort,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ExpectedInboundPort,
        [Parameter(Mandatory = $true)][ValidateSet('tcp', 'udp')][string]$Network,
        [Parameter(Mandatory = $true)][string]$ExpectedRoute,
        [Parameter(Mandatory = $true)][string[]]$ExpectedChain,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 35
    )

    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $ApiResponded = $false
    $Observed = $false
    $SnapshotCount = 0
    $Evidence = $null
    while ([DateTime]::UtcNow -lt $Deadline -and -not $Observed) {
        try {
            $Snapshot = Get-MihomoConnectionsSnapshot $ControllerPort $ControllerSecret $MihomoOwner
            $ApiResponded = $true
            $SnapshotCount++
            foreach ($Connection in @($Snapshot.connections)) {
                $Evidence = Get-MihomoConnectionRouteEvidence $Connection $TargetAddress $TargetPort `
                    $ExpectedInboundPort $Network $ExpectedRoute $ExpectedChain
                if ($null -ne $Evidence) {
                    $Observed = $true
                    break
                }
            }
        }
        catch {
        }
        if ($Observed) {
            break
        }
        $Pending = $false
        foreach ($Process in $RequestProcesses) {
            if ($null -ne $Process -and -not $Process.HasExited) {
                $Pending = $true
                break
            }
        }
        if (-not $Pending) {
            break
        }
        Start-Sleep -Milliseconds 25
    }
    return [pscustomobject]@{
        Observed = $Observed
        ApiResponded = $ApiResponded
        SnapshotCount = $SnapshotCount
        Evidence = $Evidence
    }
}

function Wait-MihomoRouteEvidenceBatch {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Requests,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 35
    )

    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $EvidenceByKey = @{}
    while ([DateTime]::UtcNow -lt $Deadline) {
        $Pending = $false
        foreach ($Request in $Requests) {
            $Key = [string]$Request.Key
            if ($EvidenceByKey.ContainsKey($Key) -and
                [bool]$EvidenceByKey[$Key].Observed) {
                continue
            }
            $Process = $Request.Process
            $Pending = $true
            $State = if ($EvidenceByKey.ContainsKey($Key)) {
                $EvidenceByKey[$Key]
            } else {
                [pscustomobject]@{
                    Key = $Key
                    Observed = $false
                    ApiResponded = $false
                    SnapshotCount = 0
                    Evidence = $null
                }
            }
            try {
                $Snapshot = Get-MihomoConnectionsSnapshot `
                    $Request.ControllerPort $Request.ControllerSecret $Request.MihomoOwner
                $State.ApiResponded = $true
                $State.SnapshotCount++
                foreach ($Connection in @($Snapshot.connections)) {
                    $Evidence = Get-MihomoConnectionRouteEvidence $Connection `
                        $Request.TargetAddress $Request.TargetPort `
                    $Request.ExpectedInboundPort $Request.ExpectedNetwork `
                    $Request.ExpectedRoute $Request.ExpectedChain
                    if ($null -ne $Evidence) {
                        $State.Evidence = $Evidence
                        $State.Observed = $true
                        break
                    }
                }
            }
            catch {
            }
            $EvidenceByKey[$Key] = $State
        }
        if (-not $Pending) {
            break
        }
        Start-Sleep -Milliseconds 25
    }
    return @($EvidenceByKey.Values)
}

function Set-MihomoProxyEndpoint {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName,
        [Parameter(Mandatory = $true)][string]$ServerAddress,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $Lines = [System.Collections.Generic.List[string]]::new()
    Assert-MihomoYamlSupportedSyntax $Yaml
    $Section = ''
    $CurrentProxy = ''
    $ServerUpdated = 0
    $PortUpdated = 0
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $Section = $Entry.Key
            $CurrentProxy = ''
            $Lines.Add($Line)
            continue
        }
        if ($Section -eq 'proxies' -and $Entry -and $Entry.IsSequence -and
            $Entry.Indent -eq 2 -and $Entry.Key -eq 'name') {
            $CurrentProxy = ConvertFrom-MihomoYamlScalar $Entry.Value
        }
        if ($Section -eq 'proxies' -and $CurrentProxy -eq $ProxyName -and $Entry -and
            -not $Entry.IsSequence -and $Entry.Indent -eq 4 -and $Entry.Key -eq 'server') {
            $Lines.Add((' ' * $Entry.Indent) + 'server: ' + $ServerAddress)
            $ServerUpdated++
            continue
        }
        if ($Section -eq 'proxies' -and $CurrentProxy -eq $ProxyName -and $Entry -and
            -not $Entry.IsSequence -and $Entry.Indent -eq 4 -and $Entry.Key -eq 'port') {
            if ((ConvertFrom-MihomoYamlScalar $Entry.Value) -notmatch '^\d+$') {
                throw 'Selected QUIC outbound must declare a numeric port field'
            }
            $Lines.Add((' ' * $Entry.Indent) + 'port: ' + $Port)
            $PortUpdated++
            continue
        }
        $Lines.Add($Line)
    }
    if ($ServerUpdated -ne 1 -or $PortUpdated -ne 1) {
        throw 'Selected QUIC outbound must declare server and numeric port fields'
    }
    return $Lines -join "`n"
}

function Set-MihomoProxyServerAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ServerAddress
    )

    if (-not (Test-MihomoLoopbackAddress $ServerAddress)) {
        throw 'Mihomo test server address must be loopback'
    }
    Assert-MihomoYamlSupportedSyntax $Yaml
    $Lines = [System.Collections.Generic.List[string]]::new()
    $Section = ''
    $Updated = 0
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $Section = $Entry.Key
            $Lines.Add($Line)
            continue
        }
        if ($Section -eq 'proxies' -and $Entry -and -not $Entry.IsSequence -and
            $Entry.Indent -eq 4 -and $Entry.Key -eq 'server') {
            $ExistingServer = ConvertFrom-MihomoYamlScalar $Entry.Value
            if (-not [string]::Equals($ExistingServer, 'socks5.preview',
                    [System.StringComparison]::Ordinal)) {
                $Lines.Add((' ' * $Entry.Indent) + 'server: ' + $ServerAddress)
                $Updated++
                continue
            }
        }
        $Lines.Add($Line)
    }
    if ($Updated -eq 0) {
        throw 'Mihomo template has no replaceable proxy server endpoint'
    }
    return $Lines -join "`n"
}

function Remove-MihomoUnusedListenerLines {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    $Lines = [System.Collections.Generic.List[string]]::new()
    $SkipNestedSection = $false
    $RemovedSections = @(
        'socks-port', 'redir-port', 'tproxy-port', 'port',
        'external-controller', 'external-controller-cors', 'external-controller-pipe',
        'external-controller-unix', 'external-controller-tls', 'secret', 'tun', 'listeners')
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $SectionName = $Entry.Key
            $SkipNestedSection = $SectionName -in @(
                'external-controller-cors', 'tun', 'listeners')
            if ($SectionName -in $RemovedSections) {
                continue
            }
            $SkipNestedSection = $false
            $Lines.Add($Line)
            continue
        }
        if ($SkipNestedSection) {
            continue
        }
        $Lines.Add($Line)
    }
    return $Lines -join "`n"
}

function Remove-MihomoNamedListenerSection {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    Assert-MihomoYamlSupportedSyntax $Yaml
    $Lines = [System.Collections.Generic.List[string]]::new()
    $SkipNestedSection = $false
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $SkipNestedSection = $Entry.Key -eq 'listeners'
            if ($SkipNestedSection) {
                continue
            }
            $Lines.Add($Line)
            continue
        }
        if (-not $SkipNestedSection) {
            $Lines.Add($Line)
        }
    }
    return $Lines -join "`n"
}

function Remove-MihomoControllerSettings {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    $Lines = [System.Collections.Generic.List[string]]::new()
    $SkipNestedSection = $false
    $RemovedSections = @(
        'external-controller', 'external-controller-pipe', 'external-controller-unix',
        'external-controller-tls', 'external-controller-cors', 'secret')
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $SectionName = $Entry.Key
            $SkipNestedSection = $SectionName -in $RemovedSections
            if ($SkipNestedSection) {
                continue
            }
            $Lines.Add($Line)
            continue
        }
        if (-not $SkipNestedSection) {
            $Lines.Add($Line)
        }
    }
    return $Lines -join "`n"
}

function Remove-MihomoTopLevelSections {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $RemovedNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Name in $Names) {
        [void]$RemovedNames.Add($Name)
    }
    $Lines = [System.Collections.Generic.List[string]]::new()
    $SkipNestedSection = $false
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $SkipNestedSection = $RemovedNames.Contains($Entry.Key)
            if ($SkipNestedSection) {
                continue
            }
            $Lines.Add($Line)
            continue
        }
        if (-not $SkipNestedSection) {
            $Lines.Add($Line)
        }
    }
    return $Lines -join "`n"
}

function Filter-MihomoTopLevelKeys {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string[]]$AllowedNames
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $Allowed = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Name in $AllowedNames) {
        [void]$Allowed.Add($Name)
    }
    $Lines = [System.Collections.Generic.List[string]]::new()
    $SkipNestedSection = $false
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $SkipNestedSection = -not $Allowed.Contains($Entry.Key)
            if (-not $SkipNestedSection) {
                $Lines.Add($Line)
            }
            continue
        }
        if (-not $SkipNestedSection) {
            $Lines.Add($Line)
        }
    }
    return $Lines -join "`n"
}

function Normalize-MihomoCaseNetworkConfiguration {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    # 仅规范化读取到内存的副本；完整 DNS 段会从 case 配置中剥离，源模板保持只读。
    $Yaml = Remove-MihomoTopLevelSections $Yaml @(
        'dns', 'ntp', 'tunnels', 'sub-rules', 'geox-url', 'geo-update-interval',
        'external-ui', 'external-ui-name', 'external-ui-url',
        'external-doh-server', 'external-controller-routing-mark',
        'external-controller', 'external-controller-pipe', 'external-controller-unix',
        'external-controller-tls', 'external-controller-cors', 'secret', 'tls',
        'interface-name', 'routing-mark')
    $Yaml = Filter-MihomoTopLevelKeys $Yaml @(
        'mixed-port', 'socks-port', 'bind-address', 'allow-lan', 'mode',
        'geo-auto-update', 'log-level', 'proxies', 'proxy-groups', 'rules')
    return Set-MihomoTopLevelScalar $Yaml 'geo-auto-update' 'false'
}

function Remove-MihomoUnsafePathEnvironment {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Environment)

    foreach ($Key in @($Environment.Keys)) {
        if ($Key -ieq 'SAFE_PATHS' -or $Key -ieq 'SKIP_SAFE_PATH_CHECK') {
            $Environment[$Key] = $null
        }
    }
    return $Environment
}

function New-MihomoIsolatedChildEnvironment {
    $Environment = @{}
    Get-ChildItem Env: | ForEach-Object { $Environment[$_.Name] = $_.Value }
    $Environment['NO_PROXY'] = 'localhost;127.0.0.1;::1'
    $Environment['no_proxy'] = $Environment['NO_PROXY']
    foreach ($Name in @(
            'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
            'http_proxy', 'https_proxy', 'all_proxy')) {
        $Environment[$Name] = ''
    }
    return Remove-MihomoUnsafePathEnvironment $Environment
}

function Assert-MihomoNoUnexpectedDefaultProxyListener {
    param([Parameter(Mandatory = $true)][psobject]$Owner)

    if (-not (Test-MihomoOwnedProcessIdentity $Owner)) {
        throw 'The owned Mihomo process identity is unavailable while checking port 7890'
    }
    try {
        $TcpListeners = @(Get-NetTCPConnection -State Listen -LocalPort 7890 `
                -OwningProcess $Owner.Id -ErrorAction SilentlyContinue)
        $UdpListeners = @(Get-NetUDPEndpoint -LocalPort 7890 `
                -OwningProcess $Owner.Id -ErrorAction SilentlyContinue)
    }
    catch {
        throw 'Unable to verify that the isolated Mihomo process avoided port 7890'
    }
    if ($TcpListeners.Count -gt 0 -or $UdpListeners.Count -gt 0) {
        throw "Isolated Mihomo PID $($Owner.Id) unexpectedly listened on 7890"
    }
}

function Assert-MihomoNoExternalDataRules {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    foreach ($Line in (Get-MihomoYamlSection $Yaml 'rules')) {
        $Trimmed = $Line.Trim()
        if ([string]::IsNullOrWhiteSpace($Trimmed)) {
            continue
        }
        if ($Trimmed -notmatch '^-[ \t]+(?<rule>.+)$') {
            throw 'Isolated Mihomo rules must use simple scalar entries'
        }
        $RuleText = ConvertFrom-MihomoYamlScalar $Matches['rule'].Trim()
        $RuleKind = ($RuleText -split ',', 2)[0].Trim().ToUpperInvariant()
        if ($RuleKind -match '^(GEO|RULE-SET$|SUB-RULE$|SCRIPT|IP-ASN$|SRC-IP-ASN$)') {
            throw 'Isolated Mihomo rules cannot depend on external geodata or rule providers'
        }
    }
}

function Assert-MihomoCaseNetworkIsolation {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][bool]$RequireController,
        [int]$ControllerPort = 0,
        [AllowEmptyString()][string]$ControllerSecret = ''
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $AllowedKeys = @(
        'mixed-port', 'socks-port', 'bind-address', 'allow-lan', 'mode',
        'geo-auto-update', 'log-level', 'proxies', 'proxy-groups', 'rules',
        'external-controller', 'secret')
    $RootEntries = @(Get-MihomoYamlMappingEntries $Yaml | Where-Object {
            $_.Indent -eq 0 -and -not $_.IsSequence
        })
    foreach ($Entry in $RootEntries) {
        if ($Entry.Key -notin $AllowedKeys) {
            throw 'Isolated Mihomo configuration contains an unsupported top-level setting'
        }
    }

    $AutoUpdate = @($RootEntries | Where-Object { $_.Key -eq 'geo-auto-update' })
    if ($AutoUpdate.Count -ne 1 -or
        (ConvertFrom-MihomoYamlScalar $AutoUpdate[0].Value) -ne 'false') {
        throw 'Isolated Mihomo configuration must disable geodata auto-updates'
    }
    Assert-MihomoNoDnsListener $Yaml
    Assert-MihomoNoExternalDataRules $Yaml
    Assert-MihomoNoShortcutInbounds $Yaml
    Assert-MihomoNoProbeGroups $Yaml
    foreach ($Proxy in (Get-MihomoProxyEntries $Yaml)) {
        $Server = Get-MihomoProxyScalar $Yaml $Proxy.Name 'server'
        $Port = Get-MihomoProxyScalar $Yaml $Proxy.Name 'port'
        $ParsedServer = $null
        $ParsedPort = 0
        if (-not [System.Net.IPAddress]::TryParse($Server, [ref]$ParsedServer) -or
            -not (Test-MihomoLoopbackAddress $Server) -or
            -not [int]::TryParse($Port, [ref]$ParsedPort) -or
            $ParsedPort -lt 1 -or $ParsedPort -gt 65535) {
            throw 'Isolated Mihomo outbounds must use an explicit loopback server and scalar port'
        }
    }

    $Controllers = @($RootEntries | Where-Object { $_.Key -eq 'external-controller' })
    $Secrets = @($RootEntries | Where-Object { $_.Key -eq 'secret' })
    if (-not $RequireController) {
        if ($Controllers.Count -ne 0 -or $Secrets.Count -ne 0) {
            throw 'Isolated QUIC Mihomo configuration cannot expose an API controller'
        }
        return
    }
    if ($ControllerPort -lt 1 -or $ControllerPort -gt 65535 -or
        $Controllers.Count -ne 1 -or $Secrets.Count -ne 1 -or
        (ConvertFrom-MihomoYamlScalar $Controllers[0].Value) -ne "127.0.0.1:$ControllerPort" -or
        (ConvertFrom-MihomoYamlScalar $Secrets[0].Value) -cne $ControllerSecret) {
        throw 'Isolated Mihomo API must use its unique loopback controller and case secret'
    }
}

function ConvertTo-MihomoYamlStringScalar {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    return ConvertTo-Json -InputObject $Value -Compress
}

function ConvertTo-MihomoYamlHexSecretScalar {
    param([Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$Value)

    return ConvertTo-MihomoYamlStringScalar $Value
}

function Set-MihomoTopLevelScalar {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $ScalarValue = if ($Name -eq 'secret') {
        ConvertTo-MihomoYamlHexSecretScalar $Value
    } else {
        $Value
    }
    $Lines = [System.Collections.Generic.List[string]]::new()
    $Count = 0
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence -and
            [string]::Equals($Entry.Key, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            $Count++
            $Lines.Add("$Name`: $ScalarValue")
        }
        else {
            $Lines.Add($Line)
        }
    }
    if ($Count -gt 1) {
        throw "Mihomo template has repeated top-level $Name settings"
    }
    if ($Count -eq 0) {
        $Lines.Insert(0, "$Name`: $ScalarValue")
    }
    return $Lines -join "`n"
}

function Remove-MihomoUnselectedInboundKeys {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][ValidateSet('mixed-port', 'socks-port')][string]$KeepPortKey
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $RemovedKeys = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Name in @('port', 'redir-port', 'tproxy-port', 'tun', 'listeners',
            'ss-config', 'vmess-config', 'tuic-server')) {
        [void]$RemovedKeys.Add($Name)
    }
    foreach ($Name in @('mixed-port', 'socks-port')) {
        if ($Name -ne $KeepPortKey) {
            [void]$RemovedKeys.Add($Name)
        }
    }
    $Lines = [System.Collections.Generic.List[string]]::new()
    $SkipNestedSection = $false
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $SkipNestedSection = $Entry.Key -in @('tun', 'listeners', 'tuic-server')
            if ($RemovedKeys.Contains($Entry.Key)) {
                continue
            }
            $SkipNestedSection = $false
            $Lines.Add($Line)
            continue
        }
        if (-not $SkipNestedSection) {
            $Lines.Add($Line)
        }
    }
    return $Lines -join "`n"
}

function Assert-MihomoIsolatedInboundPort {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][ValidateSet('mixed-port', 'socks-port')][string]$ExpectedKey,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$ExpectedPort
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $InboundKeys = @('port', 'socks-port', 'mixed-port', 'redir-port', 'tproxy-port',
        'tun', 'listeners', 'ss-config', 'vmess-config', 'tuic-server')
    $InboundEntries = @(Get-MihomoYamlMappingEntries $Yaml | Where-Object {
            $_.Indent -eq 0 -and -not $_.IsSequence -and $_.Key -in $InboundKeys
        })
    if ($InboundEntries.Count -ne 1 -or $InboundEntries[0].Key -ne $ExpectedKey) {
        throw 'Isolated Mihomo configuration must contain only its selected proxy inbound'
    }
    $PortValue = ConvertFrom-MihomoYamlScalar $InboundEntries[0].Value
    if ($PortValue -notmatch '^\d+$' -or [int]$PortValue -ne $ExpectedPort) {
        throw 'Isolated Mihomo proxy inbound must use the requested case port'
    }
    $BindAddress = @(Get-MihomoYamlMappingEntries $Yaml | Where-Object {
            $_.Indent -eq 0 -and $_.Key -eq 'bind-address'
        })
    $AllowLan = @(Get-MihomoYamlMappingEntries $Yaml | Where-Object {
            $_.Indent -eq 0 -and $_.Key -eq 'allow-lan'
        })
    if ($BindAddress.Count -ne 1 -or
        (ConvertFrom-MihomoYamlScalar $BindAddress[0].Value) -ne '127.0.0.1' -or
        $AllowLan.Count -ne 1 -or
        (ConvertFrom-MihomoYamlScalar $AllowLan[0].Value) -ne 'false') {
        throw 'Isolated Mihomo proxy inbound must be bound to loopback with LAN access disabled'
    }
}

function Normalize-MihomoIsolatedInbound {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][ValidateSet('tcp', 'udp', 'quic')][string]$CaseKind,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    Assert-MihomoNoShortcutInbounds $Yaml
    $SocksPort = @(Get-MihomoYamlMappingEntries $Yaml | Where-Object {
            $_.Indent -eq 0 -and -not $_.IsSequence -and $_.Key -eq 'socks-port'
        })
    $MixedPort = @(Get-MihomoYamlMappingEntries $Yaml | Where-Object {
            $_.Indent -eq 0 -and -not $_.IsSequence -and $_.Key -eq 'mixed-port'
        })
    $KeepPortKey = if ($CaseKind -eq 'udp' -and $SocksPort.Count -eq 1) {
        'socks-port'
    }
    else {
        'mixed-port'
    }
    $Yaml = Set-MihomoTopLevelScalar $Yaml $KeepPortKey ([string]$Port)
    $Yaml = Remove-MihomoUnselectedInboundKeys $Yaml $KeepPortKey
    Assert-MihomoIsolatedInboundPort $Yaml $KeepPortKey $Port
    return [pscustomobject]@{
        Yaml = $Yaml
        PortKey = $KeepPortKey
    }
}

function New-MihomoUuid {
    $Bytes = [byte[]]::new(16)
    $Random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Random.GetBytes($Bytes)
        $Bytes[6] = [byte](($Bytes[6] -band 0x0f) -bor 0x40)
        $Bytes[8] = [byte](($Bytes[8] -band 0x3f) -bor 0x80)
        $Hex = [Convert]::ToHexString($Bytes).ToLowerInvariant()
        return '{0}-{1}-{2}-{3}-{4}' -f $Hex.Substring(0, 8), $Hex.Substring(8, 4), `
            $Hex.Substring(12, 4), $Hex.Substring(16, 4), $Hex.Substring(20, 12)
    }
    finally {
        [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($Bytes)
        $Random.Dispose()
    }
}

function New-MihomoQuicCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [Parameter(Mandatory = $true)][string]$PrivateKeyPath
    )

    $CertificatePath = Get-MihomoCaseArtifactPath $CaseDirectory $CertificatePath
    $PrivateKeyPath = Get-MihomoCaseArtifactPath $CaseDirectory $PrivateKeyPath
    $Rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $Certificate = $null
    try {
        $Request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=localhost', $Rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $Names = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $Names.AddDnsName('localhost')
        $Names.AddIpAddress([System.Net.IPAddress]::Loopback)
        $Request.CertificateExtensions.Add($Names.Build())
        $Certificate = $Request.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-1), [DateTimeOffset]::UtcNow.AddDays(1))
        [System.IO.File]::WriteAllText($CertificatePath, $Certificate.ExportCertificatePem(),
            [System.Text.Encoding]::ASCII)
        [System.IO.File]::WriteAllText($PrivateKeyPath, $Rsa.ExportPkcs8PrivateKeyPem(),
            [System.Text.Encoding]::ASCII)
    }
    finally {
        if ($null -ne $Certificate) {
            $Certificate.Dispose()
        }
        $Rsa.Dispose()
    }
}

function Set-MihomoProxyScalar {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName,
        [Parameter(Mandatory = $true)][ValidateSet('password', 'uuid', 'sni', 'skip-cert-verify')][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $Lines = [System.Collections.Generic.List[string]]::new()
    $ScalarValue = if ($Name -eq 'password') {
        ConvertTo-MihomoYamlHexSecretScalar $Value
    } else {
        $Value
    }
    Assert-MihomoYamlSupportedSyntax $Yaml
    $Section = ''
    $CurrentProxy = ''
    $Updated = 0
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $Section = $Entry.Key
            $CurrentProxy = ''
            $Lines.Add($Line)
            continue
        }
        if ($Section -eq 'proxies' -and $Entry -and $Entry.IsSequence -and
            $Entry.Indent -eq 2 -and $Entry.Key -eq 'name') {
            $CurrentProxy = ConvertFrom-MihomoYamlScalar $Entry.Value
        }
        if ($Section -eq 'proxies' -and $CurrentProxy -eq $ProxyName -and $Entry -and
            -not $Entry.IsSequence -and $Entry.Indent -eq 4 -and $Entry.Key -eq $Name) {
            $Lines.Add((' ' * $Entry.Indent) + $Name + ': ' + $ScalarValue)
            $Updated++
            continue
        }
        $Lines.Add($Line)
    }
    if ($Updated -ne 1) {
        throw "Selected Mihomo outbound must define exactly one $Name field"
    }
    return $Lines -join "`n"
}

function Get-MihomoProxyScalar {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName,
        [Parameter(Mandatory = $true)][ValidateSet('password', 'uuid', 'sni', 'skip-cert-verify',
            'server', 'port', 'username')][string]$Name
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $Section = ''
    $CurrentProxy = ''
    $Values = [System.Collections.Generic.List[string]]::new()
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $Section = $Entry.Key
            $CurrentProxy = ''
            continue
        }
        if ($Section -eq 'proxies' -and $Entry -and $Entry.IsSequence -and
            $Entry.Indent -eq 2 -and $Entry.Key -eq 'name') {
            $CurrentProxy = ConvertFrom-MihomoYamlScalar $Entry.Value
            continue
        }
        if ($Section -eq 'proxies' -and $CurrentProxy -eq $ProxyName -and $Entry -and
            -not $Entry.IsSequence -and $Entry.Indent -eq 4 -and $Entry.Key -eq $Name) {
            $Values.Add((ConvertFrom-MihomoYamlScalar $Entry.Value))
        }
    }
    if ($Values.Count -ne 1) {
        throw "Selected Mihomo outbound must define exactly one $Name field"
    }
    return $Values[0]
}

function Get-MihomoOptionalProxyScalar {
    param(
        [Parameter(Mandatory = $true)][string]$Yaml,
        [Parameter(Mandatory = $true)][string]$ProxyName,
        [Parameter(Mandatory = $true)][ValidateSet('disable-sni', 'servername', 'sni', 'uuid', 'password')][string]$Name
    )

    Assert-MihomoYamlSupportedSyntax $Yaml
    $Section = ''
    $CurrentProxy = ''
    $Values = [System.Collections.Generic.List[string]]::new()
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($Entry -and $Entry.Indent -eq 0 -and -not $Entry.IsSequence) {
            $Section = $Entry.Key
            $CurrentProxy = ''
            continue
        }
        if ($Section -eq 'proxies' -and $Entry -and $Entry.IsSequence -and
            $Entry.Indent -eq 2 -and $Entry.Key -eq 'name') {
            $CurrentProxy = ConvertFrom-MihomoYamlScalar $Entry.Value
            continue
        }
        if ($Section -eq 'proxies' -and $CurrentProxy -eq $ProxyName -and $Entry -and
            -not $Entry.IsSequence -and $Entry.Indent -eq 4 -and $Entry.Key -eq $Name) {
            $Values.Add((ConvertFrom-MihomoYamlScalar $Entry.Value))
        }
    }
    if ($Values.Count -gt 1) {
        throw "Selected Mihomo outbound has repeated $Name settings"
    }
    if ($Values.Count -eq 0) {
        return $null
    }
    return $Values[0]
}

function Test-MihomoSensitiveKeyName {
    param([AllowEmptyString()][string]$Name)

    return $Name -match '(?i)(pass|secret|credential|token|uuid|auth(?:orization)?|user(?:name)?|psk|api[-_]?key|client[-_]?id|private[-_]?key|access[-_]?key|cookie|bearer|key)'
}

function Add-MihomoUriSensitiveValues {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Scalar,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Values
    )

    if ([string]::IsNullOrWhiteSpace($Scalar)) {
        return
    }
    $Text = ConvertFrom-MihomoYamlScalar $Scalar
    $UriMatches = [regex]::Matches($Text,
        '(?i)[a-z][a-z0-9+.-]*://(?<userinfo>[^/\s?#@]+)@')
    foreach ($Match in $UriMatches) {
        $UserInfo = $Match.Groups['userinfo'].Value
        $Variants = [System.Collections.Generic.List[string]]::new()
        $Variants.Add($UserInfo)
        try {
            $Variants.Add([System.Uri]::UnescapeDataString($UserInfo))
        }
        catch {
        }
        foreach ($Variant in @($Variants.ToArray())) {
            if (-not [string]::IsNullOrEmpty($Variant)) {
                [void]$Values.Add($Variant)
            }
            foreach ($Part in ($Variant -split ':')) {
                if (-not [string]::IsNullOrEmpty($Part)) {
                    [void]$Values.Add($Part)
                }
            }
        }
    }
    foreach ($Match in [regex]::Matches($Text,
            '(?:[?&;#])(?<name>[^=&#;\s]+)=(?<value>[^?#&;\s]*)')) {
        $RawName = $Match.Groups['name'].Value
        $NameVariants = [System.Collections.Generic.List[string]]::new()
        $NameVariants.Add($RawName)
        try {
            $NameVariants.Add([System.Uri]::UnescapeDataString($RawName))
        }
        catch {
        }
        if (-not (@($NameVariants.ToArray() | Where-Object {
                    Test-MihomoSensitiveKeyName $_
                }).Count -gt 0)) {
            continue
        }

        $RawValue = $Match.Groups['value'].Value
        if ([string]::IsNullOrEmpty($RawValue)) {
            continue
        }
        [void]$Values.Add($RawValue)
        try {
            [void]$Values.Add([System.Uri]::UnescapeDataString($RawValue))
            [void]$Values.Add([System.Uri]::UnescapeDataString($RawValue.Replace('+', ' ')))
        }
        catch {
        }
    }
}

function Get-MihomoYamlSensitiveValues {
    param([Parameter(Mandatory = $true)][string]$Yaml)

    Assert-MihomoYamlSupportedSyntax $Yaml
    $Values = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($Line in ($Yaml -split "`r?`n")) {
        $Entry = Get-MihomoYamlMappingEntry $Line
        if ($null -ne $Entry) {
            $Scalar = $Entry.Value.Trim()
            if (Test-MihomoSensitiveKeyName $Entry.Key) {
                if ([string]::IsNullOrEmpty($Scalar) -or $Scalar -match '^[|>&*!{\[]') {
                    throw 'Mihomo template contains an unsupported block, flow, alias, or tagged credential value'
                }
                $Value = ConvertFrom-MihomoYamlScalar $Scalar
                if (-not [string]::IsNullOrEmpty($Value)) {
                    [void]$Values.Add($Value)
                }
            }
            Add-MihomoUriSensitiveValues $Scalar $Values
            continue
        }
        if ($Line.Trim() -match '^-[ \t]+(?<scalar>.+)$') {
            $Scalar = $Matches['scalar'].Trim()
            if ($Scalar -match '^[|>&*!{\[]') {
                throw 'Mihomo template contains an unsupported block, flow, alias, or tagged URL value'
            }
            Add-MihomoUriSensitiveValues $Scalar $Values
        }
    }
    return @($Values)
}

function Add-MihomoConfigurationSensitiveValues {
    param(
        [AllowNull()][object]$Node,
        [Parameter(Mandatory = $true)][System.Collections.Generic.HashSet[string]]$Values,
        [bool]$SensitiveContext = $false
    )

    if ($null -eq $Node) {
        return
    }
    if ($Node -is [string]) {
        if ($SensitiveContext -and -not [string]::IsNullOrEmpty($Node)) {
            [void]$Values.Add($Node)
        }
        return
    }
    if ($Node.GetType().IsValueType) {
        return
    }
    if ($Node -is [System.Collections.IDictionary]) {
        foreach ($Key in $Node.Keys) {
            $IsSensitive = $SensitiveContext -or (Test-MihomoSensitiveKeyName ([string]$Key))
            Add-MihomoConfigurationSensitiveValues $Node[$Key] $Values $IsSensitive
        }
        return
    }
    if ($Node -is [System.Collections.IEnumerable]) {
        foreach ($Item in $Node) {
            Add-MihomoConfigurationSensitiveValues $Item $Values $SensitiveContext
        }
        return
    }
    foreach ($Property in $Node.PSObject.Properties) {
        $IsSensitive = $SensitiveContext -or (Test-MihomoSensitiveKeyName $Property.Name)
        Add-MihomoConfigurationSensitiveValues $Property.Value $Values $IsSensitive
    }
}

function Get-MihomoConfigurationSensitiveValues {
    param([AllowNull()][object]$Configuration)

    $Values = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    Add-MihomoConfigurationSensitiveValues $Configuration $Values
    return @($Values)
}

function Protect-MihomoText {
    param(
        [AllowNull()][string]$Text,
        [AllowNull()][string[]]$SensitiveValues
    )

    if ($null -eq $Text) {
        return ''
    }
    foreach ($Value in @($SensitiveValues | Sort-Object { $_.Length } -Descending)) {
        if (-not [string]::IsNullOrEmpty($Value)) {
            $Text = [regex]::Replace($Text, [regex]::Escape($Value), '[REDACTED]',
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    return $Text
}

function Protect-MihomoObjectInPlace {
    param(
        [AllowNull()][object]$Value,
        [AllowNull()][string[]]$SensitiveValues
    )

    if ($null -eq $Value) {
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($Key in @($Value.Keys)) {
            $Item = $Value[$Key]
            if ($Item -is [string]) {
                $Value[$Key] = Protect-MihomoText $Item $SensitiveValues
            }
            else {
                Protect-MihomoObjectInPlace $Item $SensitiveValues
            }
        }
        return
    }
    if ($Value -is [System.Collections.IList]) {
        for ($Index = 0; $Index -lt $Value.Count; $Index++) {
            $Item = $Value[$Index]
            if ($Item -is [string]) {
                $Value[$Index] = Protect-MihomoText $Item $SensitiveValues
            }
            else {
                Protect-MihomoObjectInPlace $Item $SensitiveValues
            }
        }
        return
    }
    if ($Value -is [pscustomobject]) {
        foreach ($Property in $Value.PSObject.Properties) {
            if ($Property.Value -is [string]) {
                $Property.Value = Protect-MihomoText $Property.Value $SensitiveValues
            }
            else {
                Protect-MihomoObjectInPlace $Property.Value $SensitiveValues
            }
        }
    }
}

function Reduce-MihomoPrismConfigurationToQuicAccount {
    param(
        [Parameter(Mandatory = $true)][object]$Configuration,
        [Parameter(Mandatory = $true)][string]$ProtocolId,
        [Parameter(Mandatory = $true)][string]$SourceSecretReference,
        [Parameter(Mandatory = $true)][string]$CaseSecretReference,
        [Parameter(Mandatory = $true)][string]$ResolvedSecret
    )

    if ([string]::IsNullOrEmpty($ProtocolId) -or
        [string]::IsNullOrEmpty($SourceSecretReference) -or
        [string]::IsNullOrEmpty($CaseSecretReference) -or
        [string]::IsNullOrEmpty($ResolvedSecret)) {
        throw 'External Prism template must resolve one QUIC secret for its isolated case'
    }
    $SelectedProtocols = @($Configuration.Protocols | Where-Object {
            [string]::Equals([string]$_.Id, $ProtocolId,
                [System.StringComparison]::Ordinal)
        })
    if ($SelectedProtocols.Count -ne 1 -or
        $null -eq $SelectedProtocols[0].Quic -or
        -not [string]::Equals([string]$SelectedProtocols[0].Quic.CredentialSecretRef,
            $SourceSecretReference, [System.StringComparison]::Ordinal)) {
        throw 'External Prism template QUIC reference is ambiguous for its isolated case'
    }
    $MatchingAccounts = @($Configuration.Accounts | Where-Object {
            [string]::Equals([string]$_.SecretRef, $SourceSecretReference,
                [System.StringComparison]::Ordinal)
        })
    if ($MatchingAccounts.Count -ne 1) {
        throw 'External Prism template must have one account bound to the selected QUIC secret reference'
    }
    $SelectedAccount = $MatchingAccounts[0]
    $AccountCredential = $SelectedAccount.PSObject.Properties['Credential']
    if ($null -ne $AccountCredential -and $null -ne $AccountCredential.Value -and
        ((-not ($AccountCredential.Value -is [string])) -or
            -not [string]::IsNullOrEmpty($AccountCredential.Value))) {
        throw 'External Prism template must use only the selected QUIC secret reference for its account'
    }
    $AccountCredentials = $SelectedAccount.PSObject.Properties['Credentials']
    if ($null -ne $AccountCredentials -and $null -ne $AccountCredentials.Value) {
        $CredentialCount = if ($AccountCredentials.Value -is [System.Collections.IDictionary]) {
            $AccountCredentials.Value.Count
        }
        elseif ($AccountCredentials.Value -is [pscustomobject]) {
            $AccountCredentials.Value.PSObject.Properties.Count
        }
        else {
            -1
        }
        if ($CredentialCount -ne 0) {
            throw 'External Prism template must use only the selected QUIC secret reference for its account'
        }
    }
    $Configuration.Accounts = @($SelectedAccount)
    $SelectedAccount.SecretRef = $CaseSecretReference
    $SelectedProtocols[0].Quic.CredentialSecretRef = $CaseSecretReference
    $Configuration.Secrets = [ordered]@{}
    $Configuration.Secrets[$CaseSecretReference] = $ResolvedSecret
}

function Protect-MihomoCaseLogs {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [AllowNull()][string[]]$SensitiveValues
    )

    $Encoding = [System.Text.UTF8Encoding]::new($false)
    $Succeeded = $true
    $PendingDirectories = [System.Collections.Generic.Stack[string]]::new()
    $LogFiles = [System.Collections.Generic.List[string]]::new()
    try {
        $CasePath = [System.IO.Path]::GetFullPath($CaseDirectory)
        if (([System.IO.File]::GetAttributes($CasePath) -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $false
        }
        $PendingDirectories.Push($CasePath)
    }
    catch {
        return $false
    }
    while ($PendingDirectories.Count -gt 0) {
        $CurrentDirectory = $PendingDirectories.Pop()
        try {
            $Children = @(Get-ChildItem -LiteralPath $CurrentDirectory -Force -ErrorAction Stop)
        }
        catch {
            return $false
        }
        foreach ($Child in $Children) {
            try {
                $SafePath = Resolve-MihomoCaseChildPath $CaseDirectory $Child.FullName
            }
            catch {
                return $false
            }
            if (($Child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            if ($Child.PSIsContainer) {
                $PendingDirectories.Push($SafePath)
            }
            elseif ([System.IO.Path]::GetExtension($SafePath) -eq '.log') {
                $LogFiles.Add($SafePath)
            }
        }
    }
    foreach ($LogFile in $LogFiles) {
        try {
            if (([System.IO.File]::GetAttributes($LogFile) -band
                    [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $Succeeded = $false
                continue
            }
            $Text = [System.IO.File]::ReadAllText($LogFile)
            $Sanitized = Protect-MihomoText $Text $SensitiveValues
            if (-not [string]::Equals($Text, $Sanitized, [System.StringComparison]::Ordinal)) {
                [System.IO.File]::WriteAllText($LogFile, $Sanitized, $Encoding)
            }
        }
        catch {
            $Succeeded = $false
        }
    }
    return $Succeeded
}

function Invoke-MihomoCleanupAction {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][scriptblock]$Operation
    )

    try {
        $Succeeded = [bool](& $Operation)
        if (-not $Succeeded) {
            [void]$Failures.Add($Action + ' failed')
        }
        return $Succeeded
    }
    catch {
        [void]$Failures.Add($Action + ' failed (' + $_.Exception.GetType().Name + ')')
        return $false
    }
}

function Get-MihomoOwnedProcessEvidence {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('prism', 'mihomo', 'target', 'curl')]
        [string]$Role,
        [Parameter(Mandatory = $true)][psobject]$Owner
    )

    if ($null -eq $Owner.Id -or [int]$Owner.Id -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$Owner.Path) -or
        $null -eq $Owner.StartTimeUtc) {
        throw "Owned process identity evidence is incomplete for role '$Role'"
    }
    return [pscustomobject]@{
        role = $Role
        pid = [int]$Owner.Id
        path = [System.IO.Path]::GetFullPath([string]$Owner.Path)
        startTimeUtc = $Owner.StartTimeUtc.ToString('o')
    }
}

function Assert-MihomoQuicCasePath {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$MustExist
    )

    $Root = [System.IO.Path]::GetFullPath($CaseDirectory).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar)
    $Prefix = $Root + [System.IO.Path]::DirectorySeparatorChar
    $Resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not $Resolved.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'QUIC runner result path escaped its case directory'
    }
    if ((Test-Path -LiteralPath $Resolved) -ne $MustExist) {
        throw 'QUIC runner result path does not match its recorded cleanup state'
    }
}

function Assert-MihomoQuicRouteContract {
    param([Parameter(Mandatory = $true)][psobject]$Result)

    $Route = $Result.routeEvidence
    if ($Result.expectedProtocol -eq 'hysteria2') {
        $ExpectedRoute = 'Hysteria2 QUIC'
        $ExpectedLeaf = 'prism-hysteria2'
    } else {
        $ExpectedRoute = 'TUIC v5 QUIC'
        $ExpectedLeaf = 'prism-tuic'
    }
    $Chain = @($Route.chains | ForEach-Object { [string]$_ })
    $ReportedExpectedChain = @($Route.expectedChain | ForEach-Object { [string]$_ })
    $ExpectedChain = @($ExpectedLeaf, $ExpectedRoute)
    if (-not [bool]$Result.controllerRouteApiResponded -or
        [int]$Result.controllerRouteSnapshotCount -lt 1 -or
        -not [bool]$Result.routeEvidenceObserved -or
        [string]::IsNullOrWhiteSpace([string]$Route.connectionId) -or
        [string]$Route.sourceAddress -ne [string]$Result.curlSourceAddress -or
        [int]$Route.sourcePort -ne [int]$Result.curlSourcePort -or
        -not (Test-MihomoLoopbackAddress ([string]$Route.sourceAddress)) -or
        [string]$Result.curlRemoteAddress -ne '127.0.0.1' -or
        [int]$Result.curlRemotePort -ne [int]$Result.proxyPort -or
        [int]$Result.controllerListenerOwnerPid -ne [int]$Result.mihomoPid -or
        -not [bool]$Result.controllerListenerOwned -or
        -not [bool]$Result.endpointOwnershipVerified -or
        -not [string]::Equals([string]$Route.network, 'tcp',
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$Route.rule, 'Match',
            [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::IsNullOrEmpty([string]$Route.rulePayload) -or
        $ReportedExpectedChain.Count -ne $ExpectedChain.Count -or
        $Chain.Count -ne $ExpectedChain.Count) {
        throw 'QUIC result has no exact curl-source route tuple through its isolated proxy'
    }
    if ([string]$Route.expectedRoute -ne $ExpectedRoute) {
        throw 'routeEvidence.expectedRoute does not match the protocol-specific group'
    }
    if (-not [string]::Equals([string]$Route.destinationAddress, '127.0.0.1',
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'routeEvidence.destinationAddress does not identify the local target'
    }
    if ([int]$Route.destinationPort -ne [int]$Result.targetPort) {
        throw 'routeEvidence.destinationPort does not match the local target'
    }
    if ([int]$Route.inboundPort -ne [int]$Result.proxyPort) {
        throw 'routeEvidence.inboundPort does not match the isolated Mihomo proxy'
    }
    for ($ChainIndex = 0; $ChainIndex -lt $Chain.Count; $ChainIndex++) {
        if (-not [string]::Equals($ReportedExpectedChain[$ChainIndex], $ExpectedChain[$ChainIndex],
                [System.StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($Chain[$ChainIndex], $ExpectedChain[$ChainIndex],
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'QUIC route evidence does not match the case-specific selected chain'
        }
    }
}

function Assert-MihomoQuicRouteBodyCorrelationContract {
    param([Parameter(Mandatory = $true)][psobject]$Result)

    $Correlation = $Result.routeBodyCorrelationUnderSingleCurl
    $Route = $Result.routeEvidence
    $RouteChains = @($Route.chains | ForEach-Object { [string]$_ })
    $CorrelationChains = @($Correlation.chains | ForEach-Object { [string]$_ })
    if ([int]$Correlation.curlInvocationCount -ne 1) {
        throw 'routeBodyCorrelationUnderSingleCurl.curlInvocationCount must equal one'
    }
    if ([int]$Correlation.curlPid -le 0 -or
        [int]$Correlation.curlPid -ne [int]$Result.curlPid) {
        throw 'routeBodyCorrelationUnderSingleCurl.curlPid does not match the owned curl process'
    }
    if ([string]$Correlation.curlSourceAddress -ne [string]$Result.curlSourceAddress -or
        [int]$Correlation.curlSourcePort -ne [int]$Result.curlSourcePort -or
        [int]$Correlation.curlSourcePort -lt 1 -or [int]$Correlation.curlSourcePort -gt 65535) {
        throw 'routeBodyCorrelationUnderSingleCurl.curlSourceTuple is invalid'
    }
    if ([string]$Correlation.curlRemoteAddress -ne [string]$Result.curlRemoteAddress -or
        [int]$Correlation.curlRemotePort -ne [int]$Result.curlRemotePort) {
        throw 'routeBodyCorrelationUnderSingleCurl.curlRemoteTuple does not match the owned TCP socket'
    }
    if ([int]$Correlation.matchedRouteRows -ne 1) {
        throw 'routeBodyCorrelationUnderSingleCurl.matchedRouteRows must equal one'
    }
    if ([string]::IsNullOrWhiteSpace([string]$Correlation.mihomoConnectionId) -or
        [string]$Correlation.mihomoConnectionId -ne [string]$Route.connectionId) {
        throw 'routeBodyCorrelationUnderSingleCurl.mihomoConnectionId does not match the route row'
    }
    if ([string]$Correlation.destinationAddress -ne [string]$Route.destinationAddress) {
        throw 'routeBodyCorrelationUnderSingleCurl.destinationAddress does not match the route row'
    }
    if ([int]$Correlation.destinationPort -ne [int]$Route.destinationPort) {
        throw 'routeBodyCorrelationUnderSingleCurl.destinationPort does not match the route row'
    }
    if ([int]$Correlation.inboundPort -ne [int]$Route.inboundPort) {
        throw 'routeBodyCorrelationUnderSingleCurl.inboundPort does not match the route row'
    }
    if ([string]$Correlation.network -ne [string]$Route.network) {
        throw 'routeBodyCorrelationUnderSingleCurl.network does not match the route row'
    }
    if ([string]$Correlation.route -ne [string]$Route.expectedRoute) {
        throw 'routeBodyCorrelationUnderSingleCurl.route does not match the selected group'
    }
    if ($CorrelationChains.Count -ne $RouteChains.Count) {
        throw 'routeBodyCorrelationUnderSingleCurl.chains length does not match the route row'
    }
    for ($Index = 0; $Index -lt $RouteChains.Count; $Index++) {
        if (-not [string]::Equals($CorrelationChains[$Index], $RouteChains[$Index],
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'routeBodyCorrelationUnderSingleCurl.chains does not match the Mihomo API row'
        }
    }
    if (-not [string]::Equals([string]$Correlation.destinationAddress, '127.0.0.1',
            [System.StringComparison]::OrdinalIgnoreCase) -or
        [int]$Correlation.destinationPort -ne [int]$Result.targetPort) {
        throw 'routeBodyCorrelationUnderSingleCurl.targetTuple does not identify the case target'
    }
    if ([int]$Correlation.inboundPort -ne [int]$Result.proxyPort) {
        throw 'routeBodyCorrelationUnderSingleCurl.inboundPort does not identify the case proxy'
    }
    if (-not [string]::Equals([string]$Correlation.network, 'tcp',
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'routeBodyCorrelationUnderSingleCurl.network must be tcp'
    }
    if ([int]$Correlation.httpCode -ne [int]$Result.httpCode -or
        [int]$Correlation.httpCode -ne 200) {
        throw 'routeBodyCorrelationUnderSingleCurl.httpCode must match the observed HTTP 200'
    }
    if ([int]$Correlation.responseBodyBytes -ne [int]$Result.responseBodyBytes -or
        [int]$Correlation.responseBodyBytes -ne 1048576) {
        throw 'routeBodyCorrelationUnderSingleCurl.responseBodyBytes must match the exact target length'
    }
    if ([int]$Correlation.targetBodyBytes -ne [int]$Result.targetBodyBytes -or
        [int]$Correlation.targetBodyBytes -ne 1048576) {
        throw 'routeBodyCorrelationUnderSingleCurl.targetBodyBytes must match the exact target length'
    }
    if ([string]$Correlation.responseBodySha256 -ne [string]$Result.bodySha256 -or
        [string]$Correlation.responseBodySha256 -ne [string]$Correlation.targetBodySha256) {
        throw 'routeBodyCorrelationUnderSingleCurl.responseBodySha256 does not match the target body'
    }
    if ([string]$Correlation.targetBodySha256 -ne [string]$Result.targetBodySha256) {
        throw 'routeBodyCorrelationUnderSingleCurl.targetBodySha256 does not match the recorded target hash'
    }
    if (-not [bool]$Result.responseBodyMatched) {
        throw 'responseBodyMatched must be true after exact byte comparison'
    }
}

function Assert-MihomoQuicCleanupContract {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][psobject]$Result
    )

    $LogPathExists = Test-Path -LiteralPath ([string]$Result.serverLogPath) -PathType Leaf
    Assert-MihomoQuicCasePath $CaseDirectory ([string]$Result.serverLogPath) $LogPathExists
    Assert-MihomoQuicCasePath $CaseDirectory ([string]$Result.prismConfig) $false
    Assert-MihomoQuicCasePath $CaseDirectory ([string]$Result.configPath) $false
    Assert-MihomoQuicCasePath $CaseDirectory (Split-Path -Parent ([string]$Result.configPath)) $false
    Assert-MihomoQuicCasePath $CaseDirectory ([string]$Result.targetRoot) $false
    $ExpectedPeerValidation = if ($Result.certificateValidation.mihomoSkipCertVerify) {
        'disabled'
    } else {
        'enabled-by-config'
    }
    $AlpnValues = @($Result.alpn.values)
    if ($Result.serverName.wireObserved -or -not $Result.serverName.configuredValuesMatched -or
        $Result.alpn.wireObserved -isnot [bool] -or $Result.alpn.wireObserved -or
        $Result.alpn.configuredValuesMatched -isnot [bool] -or
        -not $Result.alpn.configuredValuesMatched -or
        $Result.alpn.values -isnot [array] -or $AlpnValues.Count -ne 1 -or
        $AlpnValues[0] -cne 'h3' -or
        $Result.certificateValidation.mihomoSkipCertVerify -isnot [bool] -or
        $Result.certificateValidation.runnerTrustValidation -ne 'not-independently-validated' -or
        $Result.certificateValidation.mihomoPeerValidation -ne $ExpectedPeerValidation -or
        $Result.generatedPrismProfile -isnot [bool] -or
        $Result.serverLogDiagnosticAvailable -isnot [bool] -or
        ($Result.serverLogDiagnosticAvailable -and -not $LogPathExists) -or
        $Result.serverLogExcerpt -isnot [string] -or
        $Result.serverLogExcerpt.Length -gt 4096 -or
        (-not $Result.serverLogDiagnosticAvailable -and
            -not [string]::IsNullOrEmpty([string]$Result.serverLogExcerpt)) -or
        [string]$Result.prismRelayLogCorrelation -cne 'not_available' -or
        $Result.prismRelaySessionIdWireObserved -isnot [bool] -or
        $Result.prismRelaySessionIdWireObserved) {
        throw 'QUIC result has inconsistent configuration or diagnostic evidence'
    }
    $IdentityRoles = @($Result.ownedProcessIdentities | ForEach-Object { [string]$_.role })
    $IdentityPids = @($Result.ownedProcessIdentities | ForEach-Object { [int]$_.pid })
    $IdentityByRole = @{}
    foreach ($Identity in $Result.ownedProcessIdentities) {
        $IdentityByRole[[string]$Identity.role] = $Identity
    }
    $ExpectedIdentities = @{
        prism = @([int]$Result.prismPid, [string]$Result.prismExecutable)
        mihomo = @([int]$Result.mihomoPid, [string]$Result.mihomoExecutable)
        target = @([int]$Result.targetPid, [string]$Result.targetExecutable)
        curl = @([int]$Result.curlPid, [string]$Result.curlExecutable)
    }
    if ($IdentityRoles.Count -ne 4 -or
        @($IdentityRoles | Sort-Object -Unique).Count -ne 4 -or
        @($IdentityRoles | Where-Object { $_ -notin @('prism', 'mihomo', 'target', 'curl') }).Count -gt 0 -or
        @($IdentityPids | Sort-Object -Unique).Count -ne 4 -or
        @($Result.ownedProcessIdentities | Where-Object {
                [string]::IsNullOrWhiteSpace([string]$_.path) -or
                [string]::IsNullOrWhiteSpace([string]$_.startTimeUtc)
            }).Count -gt 0 -or
        [int]$Result.prismPid -notin $IdentityPids -or
        [int]$Result.mihomoPid -notin $IdentityPids -or
        [int]$Result.targetPid -notin $IdentityPids -or
        [int]$Result.curlPid -notin $IdentityPids) {
        throw 'QUIC result lacks unique Prism, Mihomo, target, and curl process identities'
    }
    foreach ($Role in $ExpectedIdentities.Keys) {
        $ExpectedIdentity = $ExpectedIdentities[$Role]
        $RecordedIdentity = $IdentityByRole[$Role]
        if ([int]$RecordedIdentity.pid -ne [int]$ExpectedIdentity[0] -or
            -not [string]::Equals([string]$RecordedIdentity.path, [string]$ExpectedIdentity[1],
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "QUIC runner process identity does not match its '$Role' executable"
        }
    }
    foreach ($Field in @('mihomoExited', 'curlExited', 'homeRemoved', 'configRemoved',
            'processesExited', 'cleanupSucceeded', 'prismConfigRemoved', 'prismExited',
            'targetExited', 'targetRootRemoved', 'generatedCertificateRemoved',
            'generatedPrivateKeyRemoved', 'ownedProcessIdentityVerified')) {
        if (-not [bool]$Result.cleanup.$Field) {
            throw "QUIC attempt cleanup field '$Field' is not true"
        }
    }
    if (@($Result.cleanup.cleanupFailures).Count -ne 0) {
        throw 'QUIC runner recorded one or more cleanup failures'
    }
}

function Assert-MihomoQuicRunnerContract {
    param(
        [Parameter(Mandatory = $true)][string]$CaseDirectory,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Results
    )

    if ($Results.Count -lt 1) {
        throw 'QUIC runner contract requires at least one attempt'
    }
    $SeenProxyPorts = [System.Collections.Generic.HashSet[int]]::new()
    for ($Index = 0; $Index -lt $Results.Count; $Index++) {
        $Result = $Results[$Index]
        $RequiredFields = @(
            'attempt', 'expectedProtocol', 'tcpPort', 'quicPort', 'targetPort', 'proxyPort',
            'controllerPort', 'prismOperationsPort', 'exitCode', 'httpCode',
            'responseBodyMatched', 'responseBodyBytes', 'targetBodyBytes', 'bodySha256',
            'targetBodySha256', 'controllerProxiesApiResponded',
            'controllerSelectedChain', 'controllerProxiesSha256',
            'controllerRouteApiResponded', 'controllerRouteSnapshotCount',
            'routeEvidenceObserved', 'routeEvidence', 'routeBodyCorrelationUnderSingleCurl',
            'prismRelayLogCorrelation', 'prismRelaySessionIdWireObserved',
            'curlSourceAddress', 'curlSourcePort',
            'curlRemoteAddress', 'curlRemotePort', 'controllerListenerOwnerPid',
            'controllerListenerOwned', 'endpointOwnershipVerified',
            'serverLogDiagnosticAvailable', 'serverLogPath', 'serverLogExcerpt',
            'mihomoTemplatePath', 'mihomoTemplateSha256',
            'generatedPrismProfile', 'certificateValidation', 'serverName', 'alpn', 'prismPid',
            'mihomoPid', 'targetPid', 'curlPid', 'prismExecutable', 'prismSha256',
            'prismConfig', 'prismConfigSha256', 'mihomoExecutable', 'mihomoSha256',
            'targetExecutable', 'curlExecutable', 'configPath', 'configSha256', 'targetRoot',
            'ownedProcessIdentities', 'cleanup'
        )
        foreach ($Field in $RequiredFields) {
            if (-not ($Result.PSObject.Properties.Name -contains $Field)) {
                throw "QUIC attempt $Index is missing result field '$Field'"
            }
        }
        if ([int]$Result.attempt -ne ($Index + 1) -or
            $Result.expectedProtocol -notin @('hysteria2', 'tuic')) {
            throw 'QUIC runner attempts or protocol identity are invalid'
        }
        $HashFields = @('prismSha256', 'prismConfigSha256', 'mihomoSha256',
            'mihomoTemplateSha256', 'configSha256', 'bodySha256', 'targetBodySha256')
        foreach ($Field in $HashFields) {
            if ([string]$Result.$Field -notmatch '^[0-9A-F]{64}$') {
                throw "QUIC attempt $($Result.attempt) has an invalid '$Field' value"
            }
        }
        if ([string]$Result.controllerProxiesSha256 -notmatch '^[0-9A-F]{64}$') {
            throw "QUIC attempt $($Result.attempt) has an invalid proxies snapshot hash"
        }
        $TemplateName = if ($Result.expectedProtocol -eq 'hysteria2') {
            'QuicHysteria2Mihomo.yaml'
        } else {
            'QuicTuicMihomo.yaml'
        }
        $PinnedTemplateSha256 = if ($Result.expectedProtocol -eq 'hysteria2') {
            'F28C742A2CD0BFCF9A64294FADE23D0D1DE80BCB5DE6F4CFD5560DB24948558E'
        } else {
            '91314C01451CD162553F7A9239856075BFB72AA4086CD54ECD2635735DFCDB5D'
        }
        $ExpectedTemplatePath = [System.IO.Path]::GetFullPath(
            (Join-Path $PSScriptRoot $TemplateName))
        $TemplatePath = [System.IO.Path]::GetFullPath([string]$Result.mihomoTemplatePath)
        if (-not [string]::Equals($ExpectedTemplatePath, $TemplatePath,
                [System.StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $TemplatePath -PathType Leaf)) {
            throw 'QUIC runner result does not identify the protocol-specific checked-in source fixture it used'
        }
        if ([string]$Result.mihomoTemplateSha256 -cne $PinnedTemplateSha256) {
            throw 'QUIC runner result does not match the pinned protocol-specific template bytes'
        }
        if ([int]$Result.exitCode -ne 0 -or [int]$Result.httpCode -ne 200 -or
            -not [bool]$Result.responseBodyMatched -or
            [int]$Result.responseBodyBytes -ne 1048576 -or
            [int]$Result.targetBodyBytes -ne [int]$Result.responseBodyBytes -or
            [string]$Result.bodySha256 -ne [string]$Result.targetBodySha256) {
            throw 'QUIC attempt lacks exact HTTP status and literal body hash evidence'
        }
        $Ports = @($Result.tcpPort, $Result.quicPort, $Result.targetPort, $Result.proxyPort,
            $Result.controllerPort, $Result.prismOperationsPort)
        if (@($Ports | Select-Object -Unique).Count -ne $Ports.Count -or
            @($Ports | Where-Object { [int]$_ -lt 1 -or [int]$_ -gt 65535 }).Count -gt 0) {
            throw 'QUIC runner service, proxy, target, and controller ports are not isolated'
        }
        if (-not $SeenProxyPorts.Add([int]$Result.proxyPort)) {
            throw 'QUIC attempts must use a fresh isolated proxy port'
        }
        if (-not [bool]$Result.controllerProxiesApiResponded -or
            [string]$Result.controllerProxiesSha256 -notmatch '^[0-9A-F]{64}$' -or
            @($Result.controllerSelectedChain).Count -ne 2 -or
            [string]$Result.controllerSelectedChain[0] -ne
                $(if ($Result.expectedProtocol -eq 'hysteria2') { 'prism-hysteria2' } else { 'prism-tuic' }) -or
            [string]$Result.controllerSelectedChain[1] -ne
                $(if ($Result.expectedProtocol -eq 'hysteria2') { 'Hysteria2 QUIC' } else { 'TUIC v5 QUIC' })) {
            throw 'QUIC runner result lacks verified /proxies selection evidence'
        }
        Assert-MihomoQuicRouteContract $Result
        Assert-MihomoQuicRouteBodyCorrelationContract $Result
        Assert-MihomoQuicCleanupContract $CaseDirectory $Result
    }
}
