<#
.SYNOPSIS
    Builds WinBolt's first optimization targets from source: zopfli and SQLite's speedtest1,
    plus unwindtest (tools/targets/unwindtest), which makes the OS unwinder walk through
    ordinary frames, so a rewrite's exception data is checked at run time.

.DESCRIPTION
    Every Stage 4+ experiment starts from binaries built here with known flags. Output goes to
    artifacts/targets/<variant>/ (ignored by the repository); the source trees are only read.
    SQLite's amalgamation is generated once from the fossil checkout into
    artifacts/targets/sqlite-amalgamation/ with Makefile.msc (needs tclsh on PATH).

    Variants:
      o2       /O2, the plain optimized build
      guardcf  /O2 /guard:cf, which gives WinBolt a GuardCFFunctionTable to use and to keep valid
      ltcg     /O2 /GL + /LTCG: whole-program optimization without a profile
      pgo      /O2 /GL + /LTCG with MSVC PGO: /GENPROFILE, a training run, then /USEPROFILE.
               The training run is the workload WinBolt profiles and benchmarks
               (speedtest1 --memdb --size 25; zopfli --i5 on speedtest1.c), so the comparison
               with WinBolt's layout is like for like. Not built by default.
      mt       /O2 /MT: the CRT linked statically, so its exception handlers (__CxxFrameHandler4,
               __C_specific_handler) are code in the image named only by the PDB, as in most
               third-party binaries. Not built by default; meant for cxxehtest and unwindtest.
      fh3      /O2 /d2FH4-: C++ EH in the FH3 format (__CxxFrameHandler3, imported from the CRT DLL),
               as older MSVC and Rust emit. Not built by default; meant for cxxehtest and unwindtest.
      fh3mt    fh3 with /MT: the FH3 handler is code in the image with no name but the PDB's.
      ehcont   /O2 /guard:cf /guard:ehcont, linked /CETCOMPAT: a GuardEHContinuationTable, which the
               OS checks exception continuations against when user shadow stacks are enforced.
               Not built by default; meant for cxxehtest and unwindtest.

.EXAMPLE
    .\tools\targets\Build-Targets.ps1
#>
param(
    [string]$Zopfli = 'D:\zopfli-master',
    [string]$Sqlite = 'D:\projekty\SQLite',
    [string[]]$Variants = @('o2', 'guardcf'),
    # Rebuilding a target changes its timestamp, which unbinds any LBR trace of it: build only
    # what is needed.
    [string[]]$Targets = @('zopfli', 'speedtest1', 'unwindtest', 'zopflipng', 'cxxehtest'),
    # Training arguments for the pgo variant.
    [string]$SpeedtestTraining = '--memdb --size 25',
    [string]$Output = (Join-Path $PSScriptRoot '../../artifacts/targets')
)

$ErrorActionPreference = 'Stop'
$Output = [IO.Path]::GetFullPath($Output)

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) {
    Write-Error 'No Visual Studio installation with the C++ x64 tools found.'
    exit 1
}

# Runs one command line inside the x64 developer environment, in a given directory.
function Invoke-Vc([string]$Directory, [string]$CommandLine) {
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    Push-Location $Directory
    try {
        # SQLite's build compiles jimsh0.exe and then runs it by bare name, which fails when the
        # environment sets NoDefaultCurrentDirectoryInExePath. Cleared for this child cmd only.
        cmd /c "set NoDefaultCurrentDirectoryInExePath=&& call `"$vcvars`" >nul && $CommandLine"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed ($LASTEXITCODE): $CommandLine"
        }
    }
    finally {
        Pop-Location
    }
}

$compile = @{
    o2      = '/nologo /O2 /Zi /MD /W0'
    guardcf = '/nologo /O2 /Zi /MD /W0 /guard:cf'
    ltcg    = '/nologo /O2 /GL /Zi /MD /W0'
    pgo     = '/nologo /O2 /GL /Zi /MD /W0'
    mt      = '/nologo /O2 /Zi /MT /W0'
    fh3     = '/nologo /O2 /Zi /MD /W0 /d2FH4-'
    fh3mt   = '/nologo /O2 /Zi /MT /W0 /d2FH4-'
    ehcont  = '/nologo /O2 /Zi /MD /W0 /guard:cf /guard:ehcont'
}
# /DEBUGTYPE:CV,FIXUP adds the linker's fixup records to the PDB: the complete reference list
# WinBolt's Stage 4 verifier checks itself against (DesignDoc Stage 4, "Fixup oracle").
# /PROFILE would add them too, but it also implies /OPT:NOICF, which changes the code.
$link = @{
    o2      = '/DEBUG /DEBUGTYPE:CV,FIXUP /OPT:REF /OPT:ICF /INCREMENTAL:NO'
    guardcf = '/DEBUG /DEBUGTYPE:CV,FIXUP /OPT:REF /OPT:ICF /INCREMENTAL:NO /guard:cf'
    ltcg    = '/DEBUG /DEBUGTYPE:CV,FIXUP /OPT:REF /OPT:ICF /INCREMENTAL:NO /LTCG'
    pgo     = '/DEBUG /DEBUGTYPE:CV,FIXUP /OPT:REF /OPT:ICF /INCREMENTAL:NO /LTCG'
    mt      = '/DEBUG /DEBUGTYPE:CV,FIXUP /OPT:REF /OPT:ICF /INCREMENTAL:NO'
    fh3     = '/DEBUG /DEBUGTYPE:CV,FIXUP /OPT:REF /OPT:ICF /INCREMENTAL:NO'
    fh3mt   = '/DEBUG /DEBUGTYPE:CV,FIXUP /OPT:REF /OPT:ICF /INCREMENTAL:NO'
    ehcont  = '/DEBUG /DEBUGTYPE:CV,FIXUP /OPT:REF /OPT:ICF /INCREMENTAL:NO /guard:cf /guard:ehcont /CETCOMPAT'
}

# One target: compile, then link; for pgo, link instrumented, train, and relink with the
# profile. Objects go to a per-target folder (zopfli's and SQLite's object names must not collide).
function Build-Target([string]$Dir, [string]$Variant, [string]$Name, [string]$Sources, [string]$Training) {
    $objects = "obj-$Name"
    $compileLine = "(if not exist $objects mkdir $objects) && cl /c $($compile[$Variant]) /Fo:$objects\ /Fd:$($Name)_c.pdb $Sources >$Name.log"
    $linkLine = "link /nologo /OUT:$Name.exe /PDB:$Name.pdb $($link[$Variant]) $objects\*.obj"
    if ($Variant -ne 'pgo') {
        Invoke-Vc $Dir "$compileLine && $linkLine >>$Name.log"
        return
    }

    Remove-Item (Join-Path $Dir "$Name*.pgc"), (Join-Path $Dir "$Name.pgd") -ErrorAction SilentlyContinue
    Invoke-Vc $Dir "$compileLine && $linkLine /GENPROFILE /PGD:$Name.pgd >>$Name.log"
    Write-Host "  training $Name ($Training)..."
    Invoke-Vc $Dir "$Name.exe $Training >nul"
    Invoke-Vc $Dir "$linkLine /USEPROFILE /PGD:$Name.pgd >>$Name.log"
}

# SQLite amalgamation: sqlite3.c/.h generated from the checkout, once.
$amalgamation = Join-Path $Output 'sqlite-amalgamation'
if (-not (Test-Path (Join-Path $amalgamation 'sqlite3.c'))) {
    Write-Host "Generating the SQLite amalgamation from $Sqlite..."
    Invoke-Vc $amalgamation "nmake /nologo /f `"$Sqlite\Makefile.msc`" TOP=`"$Sqlite`" sqlite3.c >amalgamation.log 2>&1"
}

$zopfliSources = (Get-ChildItem (Join-Path $Zopfli 'src\zopfli\*.c')).FullName | ForEach-Object { "`"$_`"" }

# zopflipng: C++ (lodepng, zopflipng) over the zopfli library, with C++ exceptions (/EHsc) so
# the image has C++ EH tables. zopfli_bin.c has its own main. Training and benchmark input: a
# 256x256 crop of a Windows lock-screen image, artifacts/bench/zopflipng-256.png.
$zopflipngSources = @(
    (Get-ChildItem (Join-Path $Zopfli 'src\zopfli\*.c') | Where-Object Name -ne 'zopfli_bin.c').FullName
    (Get-ChildItem (Join-Path $Zopfli 'src\zopflipng\*.cc')).FullName
    (Get-ChildItem (Join-Path $Zopfli 'src\zopflipng\lodepng\*.cpp')).FullName
) | ForEach-Object { "`"$_`"" }
$zopflipngInput = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../artifacts/bench/zopflipng-256.png'))

foreach ($variant in $Variants) {
    if (-not $compile.ContainsKey($variant)) {
        Write-Error "Unknown variant '$variant' (known: $($compile.Keys -join ', '))."
        exit 1
    }

    $dir = Join-Path $Output $variant
    if ($Targets -contains 'zopfli') {
        Write-Host "Building zopfli ($variant)..."
        Build-Target $dir $variant 'zopfli' ($zopfliSources -join ' ') "--i5 -c `"$Sqlite\test\speedtest1.c`""
    }

    if ($Targets -contains 'speedtest1') {
        Write-Host "Building speedtest1 ($variant)..."
        # SQLITE_ENABLE_RTREE: speedtest1's default test set includes the R-Tree tests.
        Build-Target $dir $variant 'speedtest1' "/DSQLITE_ENABLE_RTREE /I`"$amalgamation`" `"$Sqlite\test\speedtest1.c`" `"$amalgamation\sqlite3.c`"" $SpeedtestTraining
    }

    if ($Targets -contains 'zopflipng') {
        Write-Host "Building zopflipng ($variant)..."
        Build-Target $dir $variant 'zopflipng' "/EHsc $($zopflipngSources -join ' ')" "--iterations=5 -y `"$zopflipngInput`" zopflipng-training.png"
    }

    if ($Targets -contains 'cxxehtest') {
        Write-Host "Building cxxehtest ($variant)..."
        Build-Target $dir $variant 'cxxehtest' "/EHsc `"$(Join-Path $PSScriptRoot 'cxxehtest\cxxehtest.cpp')`"" ''
    }

    if ($Targets -contains 'unwindtest') {
        Write-Host "Building unwindtest ($variant)..."
        Build-Target $dir $variant 'unwindtest' "`"$(Join-Path $PSScriptRoot 'unwindtest\unwindtest.c')`"" ''
    }
}

Get-ChildItem $Output -Recurse -Include zopfli.exe, speedtest1.exe, unwindtest.exe, zopflipng.exe, cxxehtest.exe |
    ForEach-Object { '{0,-60} {1,10:N0} bytes' -f $_.FullName.Substring($Output.Length + 1), $_.Length }
