[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param([switch]$IncludeHistoricalArtifacts)
$ErrorActionPreference = 'Stop'
$workspaceRoot = (Resolve-Path -LiteralPath $PSScriptRoot).ProviderPath
$workspacePrefix = $workspaceRoot.TrimEnd('\') + '\'
if (-not (Test-Path -LiteralPath (Join-Path $workspaceRoot 'ips-web')) -or
    -not (Test-Path -LiteralPath (Join-Path $workspaceRoot 'frontend/package-lock.json'))) {
    throw 'Run this script from the AEGIS source tree'
}
$directories = @('frontend/node_modules', 'frontend/.angular', 'frontend/dist', 'frontend/out-tsc',
                 'dist', '__pycache__', 'tests/__pycache__', 'build_tools/__pycache__', 'fonts')
$files = @('app.js', 'ui.js', 'app.css', 'index.html', 'frontend-build.json', 'frontend-licenses.txt',
           'frontend/src/app/attack-catalog.ts', 'frontend/src/mitre-attack.LICENSE.txt')
if ($IncludeHistoricalArtifacts) {
    $directories += @('artifacts', 'backup')
    $files += @('优化与验证记录.md', '性能优化验证.md')
}
foreach ($relative in ($directories + $files)) {
    $absolute = [System.IO.Path]::GetFullPath((Join-Path $workspaceRoot $relative))
    if (-not $absolute.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Cleanup target outside source tree: $relative"
    }
    $cursor = $absolute
    while ($cursor -ne $workspaceRoot) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).LinkType) { throw "Refusing linked target: $relative" }
        }
        $cursor = Split-Path -Parent $cursor
    }
    if ((Test-Path -LiteralPath $absolute) -and $PSCmdlet.ShouldProcess($absolute, 'Remove generated files')) {
        if ($directories -contains $relative) { Remove-Item -LiteralPath $absolute -Recurse -Force }
        else { Remove-Item -LiteralPath $absolute -Force }
    }
}
