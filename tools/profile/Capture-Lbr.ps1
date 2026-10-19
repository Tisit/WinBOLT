<#
.SYNOPSIS
    Stage 2 prototype: capture an ETW trace with LBR (Last Branch Record) branch stacks.

.DESCRIPTION
    Must run elevated: a kernel ETW session with sampling and CPU branch recording needs
    administrator rights. Starts the NT Kernel Logger with process, image-load and sampled-profile
    events, asks the CPU to dump its LBR on every sample, runs a workload, then stops the session
    and merges the result into one .etl (readable by WinBolt and WPA).

    The default workload searches a generated 64 MB text file with findstr.exe in a loop, which
    keeps findstr's search loop and ntdll/kernelbase file I/O hot. Pass -Workload to profile
    something else.

    Nothing is changed on the system beyond the trace session itself, which is always stopped.

.EXAMPLE
    # From an elevated PowerShell:
    .\tools\profile\Capture-Lbr.ps1

.EXAMPLE
    .\tools\profile\Capture-Lbr.ps1 -Seconds 20 -Workload { & myapp.exe --benchmark }
#>
param(
    # Merged trace to write; artifacts/ is in the repository's ignore-glob.
    [string]$Output = (Join-Path $PSScriptRoot '../../artifacts/lbr.etl'),

    # How long the default workload runs.
    [int]$Seconds = 10,

    # xperf -LastBranch filters (conditionalbranches, nearrelativecalls, nearindirectcalls,
    # nearreturns, nearindirectjumps, farbranches, kernel, user). Empty records everything,
    # which the first capture should do: the data shows what each filter does.
    [string]$Filters = '',

    # Workload to run while tracing; the default is the findstr loop described above.
    [scriptblock]$Workload,

    # No LBR: only the periodic instruction-pointer samples. For CPUs without LBR (AMD, most VMs);
    # rewrite with --ip-only, which estimates block and edge counts from these samples (DesignDoc Step 22).
    [switch]$SamplingOnly
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this from an elevated PowerShell: kernel ETW sessions with LBR need administrator rights.'
    exit 1
}

$xperf = (Get-Command xperf -ErrorAction SilentlyContinue).Source
if (-not $xperf) {
    $xperf = 'C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xperf.exe'
}
if (-not (Test-Path $xperf)) {
    Write-Error 'xperf.exe not found. Install the Windows Performance Toolkit (Windows ADK).'
    exit 1
}

# Only one NT Kernel Logger can exist. Never stop someone else's trace.
if (& $xperf -loggers 2>&1 | Select-String -SimpleMatch 'NT Kernel Logger') {
    Write-Error 'A kernel trace (NT Kernel Logger) is already running. Stop it first (xperf -stop), then rerun.'
    exit 1
}

$Output = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
$kernelEtl = [IO.Path]::ChangeExtension($Output, '.kernel.etl')

# Prepare the default workload before tracing, so its setup is not in the profile.
$workloadFile = $null
if (-not $Workload) {
    $workloadFile = Join-Path $env:TEMP 'winbolt-lbr-workload.txt'
    Write-Host 'Generating a 64 MB text file for the findstr workload...'
    $words = 'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india', 'juliet'
    $random = [Random]::new(42)
    $block = [Text.StringBuilder]::new()
    while ($block.Length -lt 1MB) {
        for ($w = 0; $w -lt 12; $w++) {
            [void]$block.Append($words[$random.Next($words.Length)]).Append(' ')
        }
        [void]$block.AppendLine()
    }
    $bytes = [Text.Encoding]::ASCII.GetBytes($block.ToString())
    $stream = [IO.File]::Create($workloadFile)
    try {
        for ($i = 0; $i -lt 64; $i++) {
            $stream.Write($bytes, 0, $bytes.Length)
        }
    }
    finally {
        $stream.Dispose()
    }
}

# 1221 x 100 ns = the fastest timer sampling xperf allows (~8 kHz): more LBR stacks per second.
$start = @(
    '-on', 'PROC_THREAD+LOADER+PROFILE',
    '-SetProfInt', '1221'
)
if (-not $SamplingOnly) {
    $start += @('-LastBranch', 'Profile')
}
if ($Filters -and -not $SamplingOnly) {
    $start += $Filters
}
$start += @('-BufferSize', '1024', '-MinBuffers', '256', '-MaxBuffers', '1024', '-f', $kernelEtl)

Write-Host "Starting kernel trace: xperf $($start -join ' ')"
& $xperf @start
if ($LASTEXITCODE -ne 0) {
    Write-Error "xperf failed to start the trace (exit code $LASTEXITCODE)."
    exit 1
}

try {
    if ($Workload) {
        & $Workload
    }
    else {
        Write-Host "Running findstr for $Seconds seconds..."
        $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
        $runs = 0
        while ([DateTime]::UtcNow -lt $deadline) {
            & "$env:SystemRoot\System32\findstr.exe" /i /c:"juliet golf zulu" $workloadFile | Out-Null
            $runs++
        }
        Write-Host "findstr ran $runs times."
    }
}
finally {
    # Stops the kernel logger and merges its buffers, with image rundown, into one file.
    Write-Host 'Stopping the trace and merging...'
    & $xperf -d $Output
    if (Test-Path $kernelEtl) {
        Remove-Item $kernelEtl
    }

    # Re-merge with compression: about 4.7x smaller, and WinBolt reads it unchanged. Keeps the
    # uncompressed trace if anything goes wrong.
    $compressed = [IO.Path]::ChangeExtension($Output, '.compressed.etl')
    & $xperf -merge $Output $compressed -compress -mergeonly
    if ($LASTEXITCODE -eq 0 -and (Test-Path $compressed) -and (Get-Item $compressed).Length -gt 0) {
        Move-Item -Force $compressed $Output
    }
    else {
        Write-Warning 'Compressing the trace failed; keeping the uncompressed one.'
        if (Test-Path $compressed) {
            Remove-Item $compressed
        }
    }
    if ($workloadFile -and (Test-Path $workloadFile)) {
        Remove-Item $workloadFile
    }
}

$size = (Get-Item $Output).Length
Write-Host ("Wrote {0} ({1:N1} MB)." -f $Output, ($size / 1MB))
