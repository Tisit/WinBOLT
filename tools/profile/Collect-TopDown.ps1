<#
.SYNOPSIS
    Stage 6 attribution: VTune microarchitecture exploration (top-down) of speedtest1 builds.

.DESCRIPTION
    Must run elevated: VTune's hardware event-based sampling needs administrator rights (or a
    loaded sampling driver with access for the user). For each executable, runs
    'vtune -collect uarch-exploration' on the benchmark workload -Repeat times, builds
    interleaved, and stores the results in artifacts/vtune/<name>-s<n> (artifacts/ is in the
    repository's ignore-glob). WinBolt reads the reports afterwards without elevation.

    The default executables are the o2 build, the WinBolt layouts in artifacts/bench (greedy
    chains, ext-TSP) and the MSVC PGO build: the top-down front-end metrics (front-end bound,
    ICache/ITLB misses, DSB coverage) show whether the layouts' difference is footprint or
    alignment, and what PGO's remaining advantage is made of.

    Differences of a few percent need many samples: at VTune's default 1 ms interval one run of
    this workload is only ~1,700 samples of instructions retired, and the default collection
    multiplexes dozens of event groups. So: a 0.1 ms interval, -allow-multiple-runs (each event
    group gets its own run instead of a time slice), and repeats. VTune's counting mode
    (pmu-collection-mode=summary) is not used: on this machine it counted only a varying part of
    each run (0.2-0.75 G of the program's fixed ~6.4 G instructions).

    Nothing is changed on the system; each result directory is replaced.

.EXAMPLE
    # From an elevated PowerShell (absolute path: an elevated shell starts in System32):
    D:\projekty\WinBOLT\tools\profile\Collect-TopDown.ps1
#>
param(
    # name = executable; names become result directories.
    [System.Collections.IDictionary]$Targets,

    # Collections per build.
    [int]$Repeat = 3,

    # Milliseconds between samples.
    [double]$SamplingInterval = 0.1,

    # Arguments for every executable: the benchmark workload.
    [string[]]$Arguments = @('--memdb', '--size', '25'),

    [string]$VTune = 'C:\Program Files (x86)\Intel\oneAPI\vtune\latest\bin64\vtune.exe'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $Targets) {
    $Targets = [ordered]@{
        'o2'     = Join-Path $root 'artifacts\targets\o2\speedtest1.exe'
        'chains' = Join-Path $root 'artifacts\bench\chains.exe'
        'exttsp' = Join-Path $root 'artifacts\bench\exttsp.exe'
        'pgo'    = Join-Path $root 'artifacts\bench\pgo.exe'
    }
}

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell (hardware sampling needs administrator rights).'
}

$results = Join-Path $root 'artifacts\vtune'
New-Item -ItemType Directory -Force $results | Out-Null
Push-Location $results
try {
    foreach ($round in 1..$Repeat) {
        foreach ($name in $Targets.Keys) {
            $exe = $Targets[$name]
            if (-not (Test-Path $exe)) {
                Write-Warning "$name`: $exe not found, skipped"
                continue
            }

            $result = Join-Path $results "$name-s$round"
            if (Test-Path $result) {
                Remove-Item -Recurse -Force $result
            }

            Write-Host "== $name ($exe), round $round of $Repeat"
            & $VTune -collect uarch-exploration -knob "sampling-interval=$SamplingInterval" -allow-multiple-runs -r $result -- $exe @Arguments | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "vtune failed for $name (exit $LASTEXITCODE)"
            }
        }
    }
}
finally {
    Pop-Location
}

Write-Host "Results in $results"
