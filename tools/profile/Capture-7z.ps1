<#
.SYNOPSIS
    Captures the LBR trace of the 7-Zip benchmark workload (artifacts/lbr-7z.etl). Run elevated.

.DESCRIPTION
    The workload is the one bench uses: 7z.exe a -mx=5 -mmt=1 on a 4 MB text file
    (artifacts/7z/input.txt), about 1 s per run, deterministic output. artifacts/7z/base holds the
    7z.exe and 7z.dll it traces; the rewritten 7z.dll is bound to the trace by its image identity.

.EXAMPLE
    # elevated PowerShell:
    D:\projekty\WinBOLT\tools\profile\Capture-7z.ps1
#>
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
    [int]$Runs = 12
)

$exe = Join-Path $Root 'artifacts\7z\base\7z.exe'
$input = Join-Path $Root 'artifacts\7z\input.txt'
$archive = Join-Path $Root 'artifacts\7z\trace.7z'
$out = Join-Path $Root 'artifacts\lbr-7z.etl'
$workload = [scriptblock]::Create("1..$Runs | ForEach-Object { & '$exe' a -y -mx=5 -mmt=1 '$archive' '$input' | Out-Null }")
& (Join-Path $PSScriptRoot 'Capture-Lbr.ps1') -Output $out -Workload $workload
