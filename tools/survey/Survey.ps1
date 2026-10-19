<#
.SYNOPSIS
Coverage survey (DesignDoc 16 R2, "Coverage survey across toolchains").

.DESCRIPTION
Runs `winbolt analyze` on binaries from many toolchains and records, per binary: architecture,
MSVC Rich header (MSVC linker vs lld/GNU ld), layout provenance, PDB, the share of code that is
FullyTransformable / RelocatableOnly / Frozen, and the top reasons code is frozen.

The target paths are this machine's (Steam library, VS Code, VS LLVM tools, Git, VLC, 7-Zip,
Python): edit $Targets elsewhere. Missing files are skipped. Results: one .txt per binary and
survey.json in the output directory (default: artifacts/survey). Needs a Release CLI build.

.EXAMPLE
powershell -File tools\survey\Survey.ps1 [-OutputDirectory dir]
#>
param([string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$cli = Join-Path $root 'src\WinBolt.Cli\bin\Release\net10.0\WinBolt.Cli.exe'
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts\survey' }
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$S = 'D:\SteamLibrary\SteamApps\common'
$C = Join-Path $env:LOCALAPPDATA 'Programs\Microsoft VS Code\04c0d99f4f'
$Llvm = 'C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\Llvm\x64\bin'
$nuget = Join-Path $env:USERPROFILE '.nuget\packages\runtime.win-x64.microsoft.dotnet.ilcompiler\10.0.9\tools\ilc.exe'

$Targets = @(
    # label, group, path
    , @('Factorio', 'game: in-house engine', "$S\Factorio\bin\x64\factorio.exe")
    , @('Blue Prince UnityPlayer', 'game: Unity engine', "$S\Blue Prince\UnityPlayer.dll")
    , @('Blue Prince GameAssembly', 'game: Unity IL2CPP game code', "$S\Blue Prince\GameAssembly.dll")
    , @('Vampire Survivors GameAssembly', 'game: Unity IL2CPP game code', "$S\Vampire Survivors\GameAssembly.dll")
    , @('Outer Wilds UnityPlayer', 'game: Unity engine', "$S\Outer Wilds\UnityPlayer.dll")
    , @('Brotato', 'game: Godot', "$S\Brotato\Brotato.exe")
    , @('Slay the Spire 2', 'game: Godot', "$S\Slay the Spire 2\SlayTheSpire2.exe")
    , @('XCOM 2', 'game: Unreal 3', "$S\XCOM 2\Binaries\Win64\XCom2.exe")
    , @('MGS V TPP', 'game: in-house engine', "$S\MGS_TPP\mgsvtpp.exe")
    , @('Loop Hero', 'game: GameMaker', "$S\Loop Hero\Loop Hero.exe")
    , @('ELDEN RING', 'game: protected', "$S\ELDEN RING\Game\eldenring.exe")
    , @('VS Code (Electron)', 'app: Chromium/clang-cl', "$C\..\Code.exe")
    , @('libGLESv2 (ANGLE)', 'app: Chromium/clang-cl', "$C\libGLESv2.dll")
    , @('ripgrep', 'app: Rust', "$C\resources\app\node_modules.asar.unpacked\@github\copilot-sdk-win32-x64\ripgrep\bin\win32-x64\rg.exe")
    , @('libvlccore', 'app: VLC (mingw)', 'C:\Program Files\VideoLAN\VLC\libvlccore.dll')
    , @('git', 'app: MinGW GCC', 'C:\Program Files\Git\mingw64\bin\git.exe')
    , @('libcurl', 'app: MinGW GCC', 'C:\Program Files\Git\mingw64\bin\libcurl-4.dll')
    , @('clang', 'app: LLVM tools (VS)', "$Llvm\clang.exe")
    , @('lld-link', 'app: LLVM tools (VS)', "$Llvm\lld-link.exe")
    , @('7z.dll', 'app: MSVC', 'C:\Program Files\7-Zip\7z.dll')
    , @('python38.dll', 'app: MSVC', (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python38\python38.dll'))
    , @('ilc.exe', 'app: .NET NativeAOT', $nuget)
    , @('aotbench (sample)', 'app: .NET NativeAOT', (Join-Path $root 'artifacts\aot\aotbench\aotbench.exe'))
)

function Get-PeInfo([string]$Path) {
    $fs = [IO.File]::OpenRead($Path)
    try {
        $head = New-Object byte[] 4096
        $n = $fs.Read($head, 0, 4096)
    } finally { $fs.Dispose() }
    $pe = [BitConverter]::ToInt32($head, 0x3c)
    $machine = [BitConverter]::ToUInt16($head, $pe + 4)
    # 'Rich' (52 69 63 68) anywhere in the DOS stub / Rich header area, head[0x40:pe]
    $rich = $false
    for ($i = 0x40; $i -le $pe - 4 -and $i + 4 -le $n; $i++) {
        if ($head[$i] -eq 0x52 -and $head[$i + 1] -eq 0x69 -and $head[$i + 2] -eq 0x63 -and $head[$i + 3] -eq 0x68) { $rich = $true; break }
    }
    $arch = switch ($machine) { 0x8664 { 'x64' } 0x14c { 'x86' } 0xaa64 { 'arm64' } default { '0x{0:x}' -f $machine } }
    return @{ Arch = $arch; Rich = $rich }
}

function Get-Number([string]$s) { return [int64]($s -replace ',', '') }

function Read-Analysis([string]$Text) {
    $r = [ordered]@{}
    $r.provenance = if ($Text -match 'Layout provenance: (\S+)') { $Matches[1] } else { '?' }
    $r.pdb = if ($Text -match 'PDB: (.*)' -and -not $Matches[1].StartsWith('none')) { 'yes' } else { 'no' }
    foreach ($level in 'FullyTransformable', 'RelocatableOnly', 'Frozen') {
        $r[$level] = if ($Text -match ($level + '\s+[\d,]+ functions \(\s*[\d.]+%\),\s+([\d,]+) bytes \(([\d.]+)% of code\)')) { [double]::Parse($Matches[2], [Globalization.CultureInfo]::InvariantCulture) } else { $null }
    }
    $r.functions = if ($Text -match 'Functions: ([\d,]+)') { $Matches[1] } else { '?' }
    $r.code = if ($Text -match 'Executable bytes: ([\d,]+)') { $Matches[1] } else { '?' }
    $reasons = @()
    if ($Text -match '(?s)reason\s+functions\s+bytes\s+only reason\s+bytes\n(.*?)\n\n') {
        foreach ($line in $Matches[1] -split "`n") {
            if ($line -match '^\s+(\S+)\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)') {
                $reasons += [pscustomobject]@{ reason = $Matches[1]; bytes = Get-Number $Matches[3]; onlyReasonBytes = Get-Number $Matches[5] }
            }
        }
    }
    # stable: ties keep the report's order (Sort-Object alone is not stable)
    $i = 0
    $r.reasons = @($reasons | ForEach-Object { $_ | Add-Member -NotePropertyName idx -NotePropertyValue ($i++) -PassThru } |
        Sort-Object -Property @{ Expression = 'bytes'; Descending = $true }, @{ Expression = 'idx'; Descending = $false } |
        Select-Object -First 4 -Property reason, bytes, onlyReasonBytes)
    return $r
}

function Invoke-Analyze([string]$Path) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $cli
    $psi.Arguments = 'analyze "' + $Path + '"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEndAsync()   # both streams drained concurrently: no pipe deadlock
    $err = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(1800000)) {
        try { $p.Kill() } catch { }
        return 'TIMEOUT'
    }
    $p.WaitForExit()
    return ($out.Result + $err.Result) -replace "`r`n", "`n"
}

$utf8 = New-Object Text.UTF8Encoding($false)
$results = @()
foreach ($t in $Targets) {
    $label, $group, $path = $t[0], $t[1], [IO.Path]::GetFullPath($t[2])
    if (-not (Test-Path -LiteralPath $path)) { Write-Host "missing: ${label}: $path"; continue }
    $info = Get-PeInfo $path
    $entry = [ordered]@{
        label = $label; group = $group; arch = $info.Arch; rich = $info.Rich
        size_mb = [math]::Round((Get-Item -LiteralPath $path).Length / 1MB, 1)
    }
    if ($info.Arch -eq 'x64') {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $text = Invoke-Analyze $path
        $entry.seconds = [int][math]::Round($sw.Elapsed.TotalSeconds)
        [IO.File]::WriteAllText((Join-Path $OutputDirectory (($label -replace '\W+', '_') + '.txt')), $text, $utf8)
        foreach ($kv in (Read-Analysis $text).GetEnumerator()) { $entry[$kv.Key] = $kv.Value }
        $entry.error = if ($text.Contains('Safety gate')) { $null } else { $text.Substring(0, [math]::Min(300, $text.Length)) }
    }
    $results += [pscustomobject]$entry
    Write-Host ($entry | ConvertTo-Json -Compress -Depth 4)
}

[IO.File]::WriteAllText((Join-Path $OutputDirectory 'survey.json'), (ConvertTo-Json -InputObject @($results) -Depth 5), $utf8)
