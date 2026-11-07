# secmonk-inventory.ps1 - READ-ONLY software inventory of a Windows host for sec-monk.
#
# Emits ONE JSON document (schema "secmonk-windows-inventory/1") on stdout (UTF-8, no BOM),
# or into a file. Nothing is installed, changed or loaded: only registry reads, file reads and
# the standard Appx / CIM cmdlets that ship with Windows. PowerShell 5.1 compatible (no modules).
#
# Usage (local):
#   powershell -NoProfile -ExecutionPolicy Bypass -File secmonk-inventory.ps1 -OutFile C:\Temp\inv.json
#   powershell -NoProfile -ExecutionPolicy Bypass -File secmonk-inventory.ps1 > inv.json   (use -OutFile; '>' makes UTF-16 in 5.1)
# Usage (remote, script on stdin):
#   ssh user@win "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -" < secmonk-inventory.ps1
# Options (no param() block on purpose, so the script also works when piped on stdin):
#   -OutFile <path>   write the JSON to a file (or env SECMONK_OUTFILE)
#   -Winget           also run `winget export` (slow, per-user; or env SECMONK_WINGET=1)
# Run elevated (Administrator / SYSTEM) to see Appx packages of all users; works unelevated too.
# Keep this file ASCII-only: it is sent through ssh / Intune / consoles with unknown code pages.

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$ScriptVersion = '1.0'
$outFile = $env:SECMONK_OUTFILE
$withWinget = ($env:SECMONK_WINGET -eq '1')
for ($i = 0; $i -lt $args.Count; $i++) {
    if (([string]$args[$i]) -eq '-OutFile' -and ($i + 1) -lt $args.Count) { $outFile = [string]$args[$i + 1]; $i++ }
    elseif (([string]$args[$i]) -eq '-Winget') { $withWinget = $true }
}

$warnings = New-Object System.Collections.Generic.List[string]
function Add-Warn($m) { [void]$warnings.Add([string]$m) }
function S($v) { if ($null -eq $v) { return $null } else { return [string]$v } }
function IsoDate($d) {
    if ($null -eq $d) { return $null }
    if ($d -is [datetime]) { return $d.ToString('yyyy-MM-dd') }
    return [string]$d
}

$HKLM = [Microsoft.Win32.RegistryHive]::LocalMachine
$V64 = [Microsoft.Win32.RegistryView]::Registry64
$V32 = [Microsoft.Win32.RegistryView]::Registry32
$is64 = [Environment]::Is64BitOperatingSystem

function Open-Lm($view, $path) {
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($HKLM, $view)
        return $base.OpenSubKey($path, $false)
    } catch { return $null }
}

$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

# ---------------------------------------------------------------- OS identity
$os = [ordered]@{}
$cv = Open-Lm $V64 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if ($null -ne $cv) {
    $installEpoch = $cv.GetValue('InstallDate')
    $installIso = $null
    if ($null -ne $installEpoch) { try { $installIso = [DateTimeOffset]::FromUnixTimeSeconds([int64]$installEpoch).UtcDateTime.ToString('yyyy-MM-dd') } catch { } }
    $os['product_name'] = S $cv.GetValue('ProductName')
    $os['display_version'] = S $cv.GetValue('DisplayVersion')
    $os['release_id'] = S $cv.GetValue('ReleaseId')
    $os['current_build'] = S $cv.GetValue('CurrentBuild')
    if (-not $os['current_build']) { $os['current_build'] = S $cv.GetValue('CurrentBuildNumber') }
    $os['ubr'] = $cv.GetValue('UBR')
    $os['edition_id'] = S $cv.GetValue('EditionID')
    $os['installation_type'] = S $cv.GetValue('InstallationType')
    $os['current_version'] = S $cv.GetValue('CurrentVersion')
    $os['major'] = $cv.GetValue('CurrentMajorVersionNumber')
    $os['minor'] = $cv.GetValue('CurrentMinorVersionNumber')
    $os['build_lab_ex'] = S $cv.GetValue('BuildLabEx')
    $os['install_date'] = $installIso
    $cv.Close()
} else {
    Add-Warn 'cannot read HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
}
$arch = $null
$env64 = Open-Lm $V64 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
if ($null -ne $env64) { $arch = S $env64.GetValue('PROCESSOR_ARCHITECTURE'); $env64.Close() }
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
$os['architecture'] = $arch

# .NET Framework 4.x (registry)
$netfx = $null
$ndp = Open-Lm $V64 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
if ($null -ne $ndp) {
    $netfx = [ordered]@{ version = (S $ndp.GetValue('Version')); release = $ndp.GetValue('Release') }
    $ndp.Close()
}

# ---------------------------------------------------------------- profiles (SID -> user, loaded or not)
$profiles = @{}
$pl = Open-Lm $V64 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
if ($null -ne $pl) {
    foreach ($sidName in $pl.GetSubKeyNames()) {
        $pk = $pl.OpenSubKey($sidName, $false)
        if ($null -ne $pk) { $profiles[$sidName] = (S $pk.GetValue('ProfileImagePath')); $pk.Close() }
    }
    $pl.Close()
}
function User-Of($sid) {
    $p = $profiles[$sid]
    if ($p) { return (Split-Path -Leaf $p) }
    return $null
}

# ---------------------------------------------------------------- Uninstall keys (machine + loaded user hives)
$uninstall = New-Object System.Collections.Generic.List[object]
function Read-Uninstall($root, $hive, $scope, $sid, $user, $wow) {
    if ($null -eq $root) { return }
    foreach ($name in $root.GetSubKeyNames()) {
        $k = $null
        try { $k = $root.OpenSubKey($name, $false) } catch { }
        if ($null -eq $k) { continue }
        try {
            $dn = $k.GetValue('DisplayName')
            if ([string]::IsNullOrWhiteSpace([string]$dn)) { continue }
            [void]$uninstall.Add([ordered]@{
                hive = $hive
                scope = $scope
                sid = $sid
                user = $user
                wow6432 = $wow
                key_name = $name
                display_name = (S $dn)
                display_version = (S $k.GetValue('DisplayVersion'))
                publisher = (S $k.GetValue('Publisher'))
                install_date = (S $k.GetValue('InstallDate'))
                install_location = (S $k.GetValue('InstallLocation'))
                system_component = $k.GetValue('SystemComponent')
                windows_installer = $k.GetValue('WindowsInstaller')
                parent_key_name = (S $k.GetValue('ParentKeyName'))
                release_type = (S $k.GetValue('ReleaseType'))
            })
        } finally { $k.Close() }
    }
    $root.Close()
}
$uPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
Read-Uninstall (Open-Lm $V64 $uPath) 'HKLM' 'machine' $null $null $false
if ($is64) { Read-Uninstall (Open-Lm $V32 $uPath) 'HKLM' 'machine' $null $null $true }

$loadedSids = @()
try { $loadedSids = [Microsoft.Win32.Registry]::Users.GetSubKeyNames() } catch { Add-Warn 'cannot enumerate HKU' }
$loaded = @{}
foreach ($sid in $loadedSids) {
    if ($sid -like '*_Classes') { continue }
    if ($sid -notmatch '^S-1-(5-21|12-1)-') { continue }
    $loaded[$sid] = $true
    $user = User-Of $sid
    try {
        Read-Uninstall ([Microsoft.Win32.Registry]::Users.OpenSubKey($sid + '\' + $uPath, $false)) 'HKU' 'user' $sid $user $false
        Read-Uninstall ([Microsoft.Win32.Registry]::Users.OpenSubKey($sid + '\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', $false)) 'HKU' 'user' $sid $user $true
    } catch { Add-Warn ('HKU ' + $sid + ': ' + $_.Exception.Message) }
}
$unloaded = New-Object System.Collections.Generic.List[object]
foreach ($sid in $profiles.Keys) {
    if ($sid -notmatch '^S-1-(5-21|12-1)-') { continue }
    if (-not $loaded.ContainsKey($sid)) { [void]$unloaded.Add([ordered]@{ sid = $sid; user = (User-Of $sid); path = $profiles[$sid] }) }
}

# ---------------------------------------------------------------- Appx / MSIX
$appx = New-Object System.Collections.Generic.List[object]
try {
    if ($isAdmin) { $pkgs = Get-AppxPackage -AllUsers -ErrorAction Stop } else { $pkgs = Get-AppxPackage -ErrorAction Stop }
    foreach ($p in $pkgs) {
        [void]$appx.Add([ordered]@{
            name = (S $p.Name)
            package_full_name = (S $p.PackageFullName)
            version = (S $p.Version)
            publisher = (S $p.Publisher)
            publisher_id = (S $p.PublisherId)
            architecture = (S $p.Architecture)
            signature_kind = (S $p.SignatureKind)
            is_framework = [bool]$p.IsFramework
            non_removable = [bool]$p.NonRemovable
            install_location = (S $p.InstallLocation)
        })
    }
} catch { Add-Warn ('appx: ' + $_.Exception.Message) }

# ---------------------------------------------------------------- hotfixes (KB)
$hotfixes = New-Object System.Collections.Generic.List[object]
$qfe = $null
try { $qfe = Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop }
catch {
    try { $qfe = Get-WmiObject -Class Win32_QuickFixEngineering -ErrorAction Stop }
    catch { Add-Warn ('hotfixes: ' + $_.Exception.Message) }
}
foreach ($h in $qfe) {
    [void]$hotfixes.Add([ordered]@{
        id = (S $h.HotFixID)
        description = (S $h.Description)
        installed_on = (IsoDate $h.InstalledOn)
        installed_by = (S $h.InstalledBy)
    })
}

# ---------------------------------------------------------------- Chocolatey (nuspec files, choco.exe is not run)
$choco = New-Object System.Collections.Generic.List[object]
$chocoRoot = $env:ChocolateyInstall
if (-not $chocoRoot) { $chocoRoot = Join-Path $env:ProgramData 'chocolatey' }
$chocoLib = Join-Path $chocoRoot 'lib'
if (Test-Path -LiteralPath $chocoLib) {
    foreach ($d in (Get-ChildItem -LiteralPath $chocoLib -Directory)) {
        foreach ($f in (Get-ChildItem -LiteralPath $d.FullName -Filter '*.nuspec' -File)) {
            try {
                $x = New-Object System.Xml.XmlDocument
                $x.Load($f.FullName)
                $m = $x.package.metadata
                [void]$choco.Add([ordered]@{
                    id = (S $m.id)
                    version = (S $m.version)
                    title = (S $m.title)
                    authors = (S $m.authors)
                    project_url = (S $m.projectUrl)
                    path = $d.FullName
                })
            } catch { Add-Warn ('choco ' + $f.Name + ': ' + $_.Exception.Message) }
        }
    }
}

# ---------------------------------------------------------------- Scoop (current\manifest.json + install.json)
$scoop = New-Object System.Collections.Generic.List[object]
$scoopRoots = @{}
if ($env:SCOOP) { $scoopRoots[$env:SCOOP.ToLower()] = @{ root = $env:SCOOP; user = $env:USERNAME; global = $false } }
$gl = $env:SCOOP_GLOBAL
if (-not $gl) { $gl = Join-Path $env:ProgramData 'scoop' }
$scoopRoots[$gl.ToLower()] = @{ root = $gl; user = $null; global = $true }
foreach ($pp in $profiles.Values) {
    if ($pp) { $r = Join-Path $pp 'scoop'; if (-not $scoopRoots.ContainsKey($r.ToLower())) { $scoopRoots[$r.ToLower()] = @{ root = $r; user = (Split-Path -Leaf $pp); global = $false } } }
}
foreach ($sr in $scoopRoots.Values) {
    $apps = Join-Path $sr.root 'apps'
    if (-not (Test-Path -LiteralPath $apps)) { continue }
    foreach ($a in (Get-ChildItem -LiteralPath $apps -Directory)) {
        $mf = Join-Path $a.FullName 'current\manifest.json'
        if (-not (Test-Path -LiteralPath $mf)) { continue }
        try {
            $man = [IO.File]::ReadAllText($mf, [Text.Encoding]::UTF8) | ConvertFrom-Json
            $bucket = $null; $sarch = $null
            $ij = Join-Path $a.FullName 'current\install.json'
            if (Test-Path -LiteralPath $ij) {
                $inst = [IO.File]::ReadAllText($ij, [Text.Encoding]::UTF8) | ConvertFrom-Json
                $bucket = S $inst.bucket; $sarch = S $inst.architecture
            }
            [void]$scoop.Add([ordered]@{
                app = $a.Name
                version = (S $man.version)
                bucket = $bucket
                architecture = $sarch
                homepage = (S $man.homepage)
                root = $sr.root
                user = $sr.user
                global = [bool]$sr.global
            })
        } catch { Add-Warn ('scoop ' + $a.Name + ': ' + $_.Exception.Message) }
    }
}

# ---------------------------------------------------------------- .NET runtimes / SDKs (directory listing, dotnet.exe is not run)
$dotnetRt = New-Object System.Collections.Generic.List[object]
$dotnetSdk = New-Object System.Collections.Generic.List[object]
$nativeArch = 'x64'
if ($arch -eq 'ARM64') { $nativeArch = 'arm64' } elseif ($arch -eq 'x86') { $nativeArch = 'x86' }
$pf64 = $env:ProgramW6432
if (-not $pf64) { $pf64 = $env:ProgramFiles }
$dnRoots = New-Object System.Collections.Generic.List[object]
[void]$dnRoots.Add(@{ path = (Join-Path $pf64 'dotnet'); arch = $nativeArch })
[void]$dnRoots.Add(@{ path = (Join-Path $pf64 'dotnet\x64'); arch = 'x64' })
$pf86 = ${env:ProgramFiles(x86)}
if ($pf86) { [void]$dnRoots.Add(@{ path = (Join-Path $pf86 'dotnet'); arch = 'x86' }) }
foreach ($r in $dnRoots) {
    if (-not $r.path -or -not (Test-Path -LiteralPath $r.path)) { continue }
    $shared = Join-Path $r.path 'shared'
    if (Test-Path -LiteralPath $shared) {
        foreach ($fx in (Get-ChildItem -LiteralPath $shared -Directory)) {
            foreach ($vd in (Get-ChildItem -LiteralPath $fx.FullName -Directory)) {
                [void]$dotnetRt.Add([ordered]@{ name = $fx.Name; version = $vd.Name; arch = $r.arch; path = $vd.FullName })
            }
        }
    }
    $sdkDir = Join-Path $r.path 'sdk'
    if (Test-Path -LiteralPath $sdkDir) {
        foreach ($sd in (Get-ChildItem -LiteralPath $sdkDir -Directory)) {
            if ($sd.Name -match '^\d') { [void]$dotnetSdk.Add([ordered]@{ version = $sd.Name; arch = $r.arch; path = $sd.FullName }) }
        }
    }
}

# ---------------------------------------------------------------- winget (opt-in; never blocks longer than 90 s)
$winget = $null
if ($withWinget) {
    $winget = New-Object System.Collections.Generic.List[object]
    $wg = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $wg) { Add-Warn 'winget requested but not found' }
    else {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('secmonk-winget-' + [guid]::NewGuid().ToString('N') + '.json')
        try {
            $proc = Start-Process -FilePath $wg.Source -ArgumentList @('export', '-o', $tmp, '--include-versions', '--accept-source-agreements', '--disable-interactivity') -PassThru -WindowStyle Hidden
            if (-not $proc.WaitForExit(90000)) { try { $proc.Kill() } catch { }; Add-Warn 'winget export timed out' }
            if (Test-Path -LiteralPath $tmp) {
                $wj = [IO.File]::ReadAllText($tmp, [Text.Encoding]::UTF8) | ConvertFrom-Json
                foreach ($src in $wj.Sources) {
                    foreach ($pk in $src.Packages) {
                        [void]$winget.Add([ordered]@{ id = (S $pk.PackageIdentifier); version = (S $pk.Version); source = (S $src.SourceDetails.Name) })
                    }
                }
            }
        } catch { Add-Warn ('winget: ' + $_.Exception.Message) }
        finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force } }
    }
}

# ---------------------------------------------------------------- assemble + emit
$hostName = $env:COMPUTERNAME
$domain = $null
try { $domain = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName } catch { }
$doc = [ordered]@{
    schema = 'secmonk-windows-inventory/1'
    script_version = $ScriptVersion
    collected_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname = $hostName
    domain = $domain
    is_admin = $isAdmin
    powershell_version = (S $PSVersionTable.PSVersion)
    os = $os
    dotnet_framework = $netfx
    uninstall = $uninstall.ToArray()
    appx = $appx.ToArray()
    hotfixes = $hotfixes.ToArray()
    chocolatey = $choco.ToArray()
    scoop = $scoop.ToArray()
    winget = $(if ($null -ne $winget) { $winget.ToArray() } else { $null })
    dotnet_runtimes = $dotnetRt.ToArray()
    dotnet_sdks = $dotnetSdk.ToArray()
    unloaded_profiles = $unloaded.ToArray()
    warnings = $warnings.ToArray()
}
$json = ConvertTo-Json -InputObject $doc -Depth 6 -Compress
$utf8 = New-Object System.Text.UTF8Encoding($false)
if ($outFile) {
    [IO.File]::WriteAllText($outFile, $json, $utf8)
} else {
    $bytes = $utf8.GetBytes($json)
    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($bytes, 0, $bytes.Length)
    $stdout.Flush()
}
