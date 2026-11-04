param(
    [string]$Target = '',
    [string]$IdentityFile = '',
    [switch]$UpdateBackend,
    [switch]$UpdateNftRules,
    [switch]$NativeResponse,
    [string]$NativeResponsePackage = '',
    [switch]$WslBuild,
    [switch]$InstallSnort3,
    [switch]$UpdateEngine,
    [switch]$MigrateLogs,
    [switch]$RemoveLegacySuricata,
    [switch]$ClearNativeLogs,
    [switch]$ClearEventStream,
    [string]$EnginePackage = '',
    [string]$ReleasePackage = '',
    [string]$ReuseUiPackage = '',
    [switch]$BuildOnly,
    [string]$OutputDirectory = '',
    [ValidateRange(1,8)][Nullable[int]]$WebReadWorkers,
    [ValidateRange(0.1,10)][Nullable[double]]$CacheMemoryPercent,
    [ValidateRange(1,1024)][Nullable[int]]$CacheMaxMiB,
    [ValidateRange(128,8192)][Nullable[int]]$StatsBatchSize,
    [ValidateRange(5,80)][Nullable[double]]$StatsDutyPercent
)
$ErrorActionPreference = 'Stop'
if (-not $BuildOnly -and [string]::IsNullOrWhiteSpace($Target)) { throw 'Specify -Target user@host for deployment, or use -BuildOnly -OutputDirectory for a local build' }
if ($Target -and ($Target.StartsWith('-') -or $Target -match '\s')) { throw 'Invalid SSH target' }
if ($NativeResponse -and ($UpdateBackend -or $UpdateNftRules -or $InstallSnort3 -or $UpdateEngine -or $MigrateLogs -or $RemoveLegacySuricata -or $ClearNativeLogs -or $ReleasePackage -or $ReuseUiPackage)) { throw '-NativeResponse is a standalone adapter build or activation' }
if ($NativeResponsePackage -and -not $NativeResponse) { throw '-NativeResponsePackage requires -NativeResponse' }
if ($NativeResponse -and -not $BuildOnly -and -not (Test-Path -LiteralPath $NativeResponsePackage)) { throw '-NativeResponse activation requires an existing -NativeResponsePackage' }
if ($BuildOnly -and -not $OutputDirectory) { throw '-BuildOnly requires -OutputDirectory outside the source directory' }
if ($InstallSnort3 -and (-not $UpdateBackend -or $BuildOnly -or -not $EnginePackage)) { throw '-InstallSnort3 requires -UpdateBackend and -EnginePackage and cannot be used with -BuildOnly' }
if ($InstallSnort3 -and -not (Test-Path -LiteralPath $EnginePackage)) { throw 'Engine package is missing' }
if ($UpdateEngine -and ($InstallSnort3 -or -not $UpdateBackend -or $BuildOnly -or -not (Test-Path -LiteralPath $EnginePackage))) { throw '-UpdateEngine requires -UpdateBackend and an existing -EnginePackage, and cannot be combined with initial activation or BuildOnly' }
if ($MigrateLogs -and (-not $UpdateBackend -or $BuildOnly -or $UpdateEngine)) { throw '-MigrateLogs requires -UpdateBackend and cannot be combined with BuildOnly or UpdateEngine' }
if ($RemoveLegacySuricata -and (-not $UpdateBackend -or $BuildOnly -or $UpdateEngine -or $InstallSnort3)) { throw '-RemoveLegacySuricata requires -UpdateBackend after native activation, without an engine upgrade' }
if ($ClearNativeLogs -and (-not $UpdateBackend -or $BuildOnly -or $UpdateEngine -or $InstallSnort3)) { throw '-ClearNativeLogs requires -UpdateBackend after native activation, without an engine upgrade' }
if ($ClearEventStream -and -not $ClearNativeLogs) { throw '-ClearEventStream requires -ClearNativeLogs and explicit authorization to clear the full raw stream' }
if ($ReleasePackage -and ($BuildOnly -or -not (Test-Path -LiteralPath $ReleasePackage))) { throw '-ReleasePackage requires an existing release and cannot be combined with -BuildOnly' }
if ($ReuseUiPackage -and ($ReleasePackage -or -not (Test-Path -LiteralPath $ReuseUiPackage))) { throw '-ReuseUiPackage requires an existing UI release and cannot be combined with -ReleasePackage' }
$resourceFlags = [ordered]@{WebReadWorkers='--read-workers';CacheMemoryPercent='--cache-memory-percent';CacheMaxMiB='--cache-max-mib';StatsBatchSize='--stats-batch-size';StatsDutyPercent='--stats-duty-percent'}
$resourceArguments = @()
foreach ($parameter in $resourceFlags.Keys) {
    if ($PSBoundParameters.ContainsKey($parameter)) {
        $value = $PSBoundParameters[$parameter].ToString([System.Globalization.CultureInfo]::InvariantCulture)
        $resourceArguments += @($resourceFlags[$parameter],$value)
    }
}
if ($resourceArguments.Count -and (-not $UpdateBackend -or $BuildOnly)) { throw 'Resource settings require -UpdateBackend and cannot be used with -BuildOnly' }
if (($InstallSnort3 -or $UpdateEngine) -and $resourceArguments.Count) { throw 'Apply resource overrides with a subsequent -UpdateBackend update' }
if ($UpdateNftRules -and ($UpdateBackend -or $InstallSnort3 -or $UpdateEngine -or $BuildOnly -or $OutputDirectory -or $resourceArguments.Count)) {
    throw '-UpdateNftRules is a standalone NFQUEUE-only deployment'
}
$buildWorkspace = Join-Path ([System.IO.Path]::GetTempPath()) ('aegis-release-' + [guid]::NewGuid().ToString('N'))
$resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\','/')
$resolvedBuild = [System.IO.Path]::GetFullPath($buildWorkspace)
if (-not $resolvedBuild.StartsWith($resolvedTemp + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid temporary release directory' }
$stageReady = $false
Push-Location $PSScriptRoot
try {
    $destination = if ($BuildOnly) { [System.IO.Path]::GetFullPath($OutputDirectory) } else { $resolvedBuild }
    if ($NativeResponse) {
        if ($BuildOnly) {
            $linuxDestination = (& wsl -d Debian -- wslpath -a $destination.Replace('\','/')).Trim()
            if ($LASTEXITCODE -ne 0) { throw 'WSL response output path conversion failed' }
            & wsl -d Debian --cd $PSScriptRoot -- python3 -B package-native-response.py --output $linuxDestination
            if ($LASTEXITCODE -ne 0) { throw 'Native response adapter build failed' }
            return
        }
        & python -B -m unittest -q tests.test_native_response_deploy
        if ($LASTEXITCODE -ne 0) { throw 'Native response deployment regression failed' }
        $archive = [System.IO.Path]::GetFullPath($NativeResponsePackage)
        $fileName = Split-Path -Leaf $archive
        if ($fileName -ne 'ips-native-response-arm64-1.tar.gz') { throw 'Unexpected native response archive' }
        $expected = ((Get-Content -LiteralPath "$archive.sha256" -Raw).Trim() -split '\s+')[0]
        if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected.ToLowerInvariant()) { throw 'Native response archive checksum differs' }
        $options = @('-o','BatchMode=yes','-o','ConnectTimeout=10')
        $defaultIdentity = "$env:USERPROFILE/.ssh/id_ed25519"
        if (-not $IdentityFile -and (Test-Path -LiteralPath $defaultIdentity)) { $IdentityFile = $defaultIdentity }
        if ($IdentityFile) { $options += @('-o','IdentityAgent=none','-o','IdentitiesOnly=yes','-i',$IdentityFile) }
        $release = [guid]::NewGuid().ToString('N').Substring(0,16)
        $stage = "/var/lib/ips-deploy/release-$release"
        & ssh @options $Target "mkdir -p '$stage'"
        if ($LASTEXITCODE -ne 0) { throw 'Native response staging failed' }
        $stageReady = $true
        & scp @options $archive "$archive.sha256" ($Target + ':' + $stage + '/')
        if ($LASTEXITCODE -ne 0) { throw 'Native response upload failed' }
        & ssh @options $Target "cd '$stage' && sha256sum --strict -c '$fileName.sha256' && tar -xzf '$fileName' && cd response && sha256sum --strict -c SHA256SUMS && python3 -B deploy-native-response.py --release ."
        if ($LASTEXITCODE -ne 0) { throw 'Native response activation or verification failed' }
        return
    }
    if ($UpdateNftRules) {
        & python -B -m unittest -q tests.test_nft_rules tests.test_deploy_nft
        if ($LASTEXITCODE -ne 0) { throw 'NFQUEUE regression checks failed' }
        & python -B deploy-nft.py --prepare $destination
        if ($LASTEXITCODE -ne 0) { throw 'NFQUEUE package preparation failed' }
        $options = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10')
        $defaultIdentity = "$env:USERPROFILE/.ssh/id_ed25519"
        if (-not $IdentityFile -and (Test-Path -LiteralPath $defaultIdentity)) { $IdentityFile = $defaultIdentity }
        if ($IdentityFile) {
            if (-not (Test-Path -LiteralPath $IdentityFile)) { throw 'SSH identity file does not exist' }
            $options += @('-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes', '-i', $IdentityFile)
        }
        & ssh @options $Target 'test -r /etc/ips-snort-deployment.json && test -r /etc/snort/snort.lua'
        if ($LASTEXITCODE -ne 0) { throw 'Target has not activated this Snort 3 runtime; complete -InstallSnort3 first' }
        $release = [guid]::NewGuid().ToString('N').Substring(0,16)
        $stage = "/var/lib/ips-deploy/release-$release"
        & ssh @options $Target "mkdir -p '$stage'"
        if ($LASTEXITCODE -ne 0) { throw 'Remote staging failed' }
        $stageReady = $true
        & scp @options (Join-Path $destination 'ips-supervisor') (Join-Path $destination 'log_storage.py') (Join-Path $destination 'deploy-nft.py') (Join-Path $destination 'SHA256SUMS') ($Target + ':' + $stage + '/')
        if ($LASTEXITCODE -ne 0) { throw 'NFQUEUE upload failed' }
        & ssh @options $Target "cd '$stage' && sha256sum --strict -c SHA256SUMS && python3 -B deploy-nft.py --release ."
        if ($LASTEXITCODE -ne 0) { throw 'NFQUEUE deployment or verification failed' }
        return
    }
    if ($ReleasePackage) {
        $ReleasePackage = [System.IO.Path]::GetFullPath($ReleasePackage)
        if (-not (Test-Path -LiteralPath "$ReleasePackage.sha256")) { throw 'Release checksum is missing' }
        $expectedReleaseHash = ((Get-Content -LiteralPath "$ReleasePackage.sha256" -Raw).Trim() -split '\s+')[0]
        if ((Get-FileHash -LiteralPath $ReleasePackage -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedReleaseHash.ToLowerInvariant()) { throw 'Release checksum differs' }
        $result = @($ReleasePackage)
        $buildExit = 0
    } elseif ($WslBuild) {
        $convertedDestination = & wsl -d Debian -- wslpath -a $destination.Replace('\','/')
        if ($LASTEXITCODE -ne 0) { throw 'WSL output path conversion failed' }
        $linuxDestination = $convertedDestination.Trim()
        $reuseArguments = @()
        if ($ReuseUiPackage) {
            $linuxUiPackage = (& wsl -d Debian -- wslpath -a ([System.IO.Path]::GetFullPath($ReuseUiPackage).Replace('\','/'))).Trim()
            if ($LASTEXITCODE -ne 0) { throw 'Reusable UI path conversion failed' }
            $reuseArguments = @('--reuse-ui-package',$linuxUiPackage)
        }
        $result = & wsl -d Debian --cd $PSScriptRoot -- python3 -B package.py --output $linuxDestination @reuseArguments
        $buildExit = $LASTEXITCODE
        if ($buildExit -eq 0) { $result[0] = (& wsl -d Debian -- wslpath -w $result[0]).Trim() }
    } else {
        $reuseArguments = if ($ReuseUiPackage) { @('--reuse-ui-package',$ReuseUiPackage) } else { @() }
        $result = & python -B package.py --output $destination @reuseArguments
        $buildExit = $LASTEXITCODE
    }
    if ($buildExit -ne 0) { throw 'Package build failed' }
    $archive = $result[0].ToString()
    $result | Write-Output
    if ($BuildOnly) { return }
    $fileName = Split-Path -Leaf $archive
    $releaseMatch = [regex]::Match($fileName, '^snort-ndr-(?<release>[a-f0-9]{16})\.tar\.gz$')
    if (-not $releaseMatch.Success) { throw 'Unexpected release name' }
    $release = $releaseMatch.Groups['release'].Value
    $options = @('-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10')
    $defaultIdentity = "$env:USERPROFILE/.ssh/id_ed25519"
    if (-not $IdentityFile -and (Test-Path -LiteralPath $defaultIdentity)) { $IdentityFile = $defaultIdentity }
    if ($IdentityFile) {
        if (-not (Test-Path -LiteralPath $IdentityFile)) { throw 'SSH identity file does not exist' }
        $options += @('-o', 'IdentityAgent=none', '-o', 'IdentitiesOnly=yes', '-i', $IdentityFile)
    }
    if (-not $InstallSnort3) {
        & ssh @options $Target 'test -r /etc/ips-snort-deployment.json && test -r /etc/snort/snort.lua'
        if ($LASTEXITCODE -ne 0) { throw 'Target has not activated this Snort 3 runtime; complete -InstallSnort3 first' }
    }
    $stage = "/var/lib/ips-deploy/release-$release"
    & ssh @options $Target "mkdir -p '$stage'"
    if ($LASTEXITCODE -ne 0) { throw 'Remote staging failed' }
    $stageReady = $true
    & scp @options $archive "$archive.sha256" "${Target}:$stage/"
    if ($LASTEXITCODE -ne 0) { throw 'Upload failed' }
    $backendStep = if ($UpdateBackend) { 'python3 snort-ndr/deploy-backend.py --release snort-ndr ' + ($resourceArguments -join ' ') + ' && ' } else { '' }
    if ($InstallSnort3 -or $UpdateEngine) {
        $engineFileName = Split-Path -Leaf $EnginePackage
        if ($engineFileName -notmatch '^ips-snort3-arm64-[0-9.]+(?:-session[0-9]+)?\.tar\.gz$') { throw 'Unexpected engine package name' }
        if (-not (Test-Path -LiteralPath "$EnginePackage.sha256")) { throw 'Engine package checksum is missing' }
        & scp @options $EnginePackage "$EnginePackage.sha256" "${Target}:$stage/"
        if ($LASTEXITCODE -ne 0) { throw 'Engine upload failed' }
        $engineDeployer = if ($UpdateEngine) { 'deploy-session-engine.py' } else { 'deploy-snort3.py' }
        $backendStep = "sha256sum -c '$engineFileName.sha256' && python3 snort-ndr/$engineDeployer --release snort-ndr --engine-package '$engineFileName' && "
    }
    $staticStep = if ($InstallSnort3 -or $UpdateEngine) { 'true' } else { 'bash snort-ndr/deploy.sh --web-only' }
    if ($MigrateLogs) { $backendStep = 'python3 snort-ndr/deploy-log-storage.py --release snort-ndr && ' + $backendStep }
    if ($RemoveLegacySuricata) { $staticStep += ' && python3 snort-ndr/cleanup-legacy-suricata.py --apply' }
    if ($ClearNativeLogs) { $staticStep += ' && python3 snort-ndr/cleanup-native-logs.py --apply'; if ($ClearEventStream) { $staticStep += ' --event-stream' } }
    & ssh @options $Target "cd '$stage' && sha256sum -c '$fileName.sha256' && tar -xzf '$fileName' && ${backendStep}$staticStep"
    if ($LASTEXITCODE -ne 0) { throw 'Deployment or health check failed' }
} finally {
    if ($stageReady) {
        $cleanupCode = @'
import pathlib, shutil
p = pathlib.Path('/var/lib/ips-deploy/release-RELEASE').resolve()
assert p.parent == pathlib.Path('/var/lib/ips-deploy') and p.name == 'release-RELEASE'
shutil.rmtree(p)
'@
        try {
            $cleanupCode.Replace('RELEASE', $release) | & ssh @options $Target 'python3 -'
            if ($LASTEXITCODE -ne 0) { Write-Warning "Remote temporary directory could not be removed: $stage" }
        } catch { Write-Warning "Remote temporary directory cleanup failed: $stage" }
    }
    if (Test-Path -LiteralPath $resolvedBuild) { Remove-Item -LiteralPath $resolvedBuild -Recurse -Force }
    Pop-Location
}
