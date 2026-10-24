# Packs the Store build of the app into an MSIX for Partner Center.
#
#   pwsh packaging/msstore/pack.ps1 -Exe target/release/TrackMySign.exe -Out TrackMySign-windows-x64.msix
#
# The exe must come from `tauri build --features store` with TRACKMYSIGN_STORE=1
# (see README.md). Needs the Windows SDK (makepri.exe, makeappx.exe) and Python.
# The package is not signed: the Store signs it after certification.
param(
    [Parameter(Mandatory)] [string] $Exe,
    [Parameter(Mandatory)] [string] $Out,
    # Default: the version in tauri.conf.json.
    [string] $Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$work = Join-Path ([IO.Path]::GetTempPath()) "trackmysign-msix-$PID"
$layout = Join-Path $work 'package'
New-Item -ItemType Directory -Force -Path $layout | Out-Null

# The newest Windows SDK that has the tools.
$makeappx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.*\x64\makeappx.exe" |
    Sort-Object { [version]$_.Directory.Parent.Name } |
    Select-Object -Last 1
if (-not $makeappx) { throw 'makeappx.exe not found; install the Windows SDK' }
$bin = $makeappx.DirectoryName

Copy-Item $Exe (Join-Path $layout 'TrackMySign.exe')
Copy-Item -Recurse (Join-Path $here 'Assets') (Join-Path $layout 'Assets')

$manifest = Join-Path $layout 'AppxManifest.xml'
$fill = @((Join-Path $here 'manifest.py'), 'fill', '--out', $manifest)
if ($Version) { $fill += @('--version', $Version) }
python @fill
if ($LASTEXITCODE) { throw 'manifest.py fill failed' }
python (Join-Path $here 'manifest.py') check $manifest
if ($LASTEXITCODE) { throw 'manifest.py check failed' }

# resources.pri: lets Windows pick the targetsize-* icons (taskbar, Start).
$priconfig = Join-Path $work 'priconfig.xml'
& "$bin\makepri.exe" createconfig /cf $priconfig /dq en-US /pv 10.0.0 /o
if ($LASTEXITCODE) { throw 'makepri createconfig failed' }
& "$bin\makepri.exe" new /pr $layout /cf $priconfig /mn $manifest /of (Join-Path $layout 'resources.pri') /o
if ($LASTEXITCODE) { throw 'makepri new failed' }

# Also validates the manifest against the SDK's schemas.
& "$bin\makeappx.exe" pack /d $layout /p $Out /o
if ($LASTEXITCODE) { throw 'makeappx pack failed' }

Remove-Item -Recurse -Force $work
Write-Output "$Out ($((Get-Item $Out).Length) bytes, Windows SDK $($makeappx.Directory.Parent.Name))"
