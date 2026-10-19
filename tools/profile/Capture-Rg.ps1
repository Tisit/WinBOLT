<#
.SYNOPSIS
    Captures the LBR trace of the ripgrep benchmark workload (artifacts/lbr-rg-big.etl). Run elevated.

.DESCRIPTION
    The workload is the one bench uses: single-threaded, one 290 MB text file (artifacts/rg/big/part0.txt,
    the SQLite tree x6 plus zopfli concatenated; page cached), a regex-engine-heavy pattern. About
    0.65 s per run, of which the kernel is small. (The many-files corpus in artifacts/rg/corpus spends
    two thirds of its cycles in the kernel's file system and hides user-mode changes.)

.EXAMPLE
    # elevated PowerShell:
    D:\projekty\WinBOLT\tools\profile\Capture-Rg.ps1
#>
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path,
    [int]$Runs = 12
)

$rg = Join-Path $Root 'artifacts\rg\rg.exe'
$file = Join-Path $Root 'artifacts\rg\big\part0.txt'
$out = Join-Path $Root 'artifacts\lbr-rg-big.etl'
$workload = [scriptblock]::Create("1..$Runs | ForEach-Object { & '$rg' -j1 -uu -c -i '\b[A-Z][a-z]+_[a-z]+\s*\(\s*\w+\s*,' '$file' | Out-Null }")
& (Join-Path $PSScriptRoot 'Capture-Lbr.ps1') -Output $out -Workload $workload
