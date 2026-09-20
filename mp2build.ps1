[CmdletBinding()]
param(
    [string]$MaxPlusPath = 'C:\tools\Progs\MaxPlus2\maxplus2\maxplus2.exe',
    [string]$TransTtfPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Keep the report layout and limiting-fmax selection used by SP_Conf_Test/mp2build.ps1.
function Write-DeviceSummary {
    param([string]$ReportText)

    $pattern = '(?m)^\s*(?<Chip>\S+)\s+(?<Device>EP1K\S+)\s+(?<InputPins>[0-9]+)\s+(?<OutputPins>[0-9]+)\s+(?<BidirPins>[0-9]+)\s+(?<MemoryBits>[0-9]+)\s+(?<MemoryUsed>[0-9]+)\s*%\s+(?<LogicCells>[0-9]+)\s+(?<LogicCellsUsed>[0-9]+)\s*%\s*$'
    $summary = [regex]::Match($ReportText, $pattern, 'IgnoreCase')
    if (-not $summary.Success) {
        Write-Warning 'ACEX device summary was not found in scroll.rpt.'
        return
    }

    $tableFormat = '{0,-10} {1,-16} {2,10} {3,11} {4,10} {5,11} {6,11} {7,6} {8,8}'
    Write-Host '** DEVICE SUMMARY **'
    Write-Host ''
    Write-Host ($tableFormat -f 'Chip/POF', 'Device', 'Input Pins', 'Output Pins',
        'Bidir Pins', 'Memory Bits', 'Memory Used', 'LCs', 'LCs Used')
    Write-Host ($tableFormat -f '----------', '----------------', '----------',
        '-----------', '----------', '-----------', '-----------', '------', '--------')
    Write-Host ($tableFormat -f $summary.Groups['Chip'].Value, $summary.Groups['Device'].Value,
        $summary.Groups['InputPins'].Value, $summary.Groups['OutputPins'].Value,
        $summary.Groups['BidirPins'].Value, $summary.Groups['MemoryBits'].Value,
        ($summary.Groups['MemoryUsed'].Value + ' %'), $summary.Groups['LogicCells'].Value,
        ($summary.Groups['LogicCellsUsed'].Value + ' %'))
}

function Write-TimingSummary {
    param([string]$ReportText)

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $pattern = '(?m)^\s*fmax\s+.+?\s+(?<Assignment>[0-9]+(?:\.[0-9]+)?)\s+MHz\s+(?<Actual>[0-9]+(?:\.[0-9]+)?)\s+MHz[^\r\n]*\r?$'
    $frequencies = @([regex]::Matches($ReportText, $pattern, 'IgnoreCase') | ForEach-Object {
        [double]::Parse($_.Groups['Actual'].Value, $culture)
    })

    Write-Host '=== timing summary ==='
    if ($frequencies.Count -eq 0) {
        Write-Warning 'Maximum clock frequency (fmax) was not found in scroll.rpt.'
        return
    }

    $limitingFmax = $frequencies | Measure-Object -Minimum
    $fmaxText = $limitingFmax.Minimum.ToString('0.00', $culture)
    Write-Host "Maximum clock frequency (fmax): $fmaxText MHz" -ForegroundColor Cyan
}

function Invoke-BuildTool {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$LogName,
        [hashtable]$EnvironmentOverrides = @{}
    )

    $stdoutPath = Join-Path $WorkingDirectory ($LogName + '.txt')
    $stderrPath = Join-Path $WorkingDirectory ($LogName + '_stderr.txt')
    $savedEnvironment = @{}
    try {
        foreach ($name in $EnvironmentOverrides.Keys) {
            $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            [Environment]::SetEnvironmentVariable($name, $EnvironmentOverrides[$name], 'Process')
        }
        $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments `
            -WorkingDirectory $WorkingDirectory -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        # -Wait also waits for descendants such as the legacy printer host splwow64.
        # Cache the native handle so PowerShell 5.1 retains the process exit code.
        $processHandle = $process.Handle
        $process.WaitForExit()
        $process.Refresh()
        $exitCode = $process.ExitCode
    }
    finally {
        foreach ($name in $savedEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
        }
    }

    $outputLines = @(Get-Content -LiteralPath $stdoutPath -Encoding Default)
    $errorLines = @(Get-Content -LiteralPath $stderrPath -Encoding Default)
    if ($errorLines.Count -gt 0) {
        Add-Content -LiteralPath $stdoutPath -Value $errorLines -Encoding Default
        $outputLines += $errorLines
    }
    $outputLines | ForEach-Object { Write-Host $_ }

    return [pscustomobject]@{
        ExitCode = $exitCode
        OutputLines = $outputLines
    }
}

function New-CompilerEnvironment {
    param([string]$CompilerPath, [string]$ProjectDirectory)

    $compilerDirectory = Split-Path -Parent $CompilerPath
    $privateRoot = Join-Path $ProjectDirectory '_mp2'
    foreach ($name in @('ini', 'work', 'tmp')) {
        New-Item -ItemType Directory -Path (Join-Path $privateRoot $name) -Force | Out-Null
    }
    $updates = @{
        WORK_DIR = Join-Path $privateRoot 'work'
        DESIGN_NAME = Join-Path $ProjectDirectory 'scroll'
        AUTO_RELOAD_LAST_PROJECT = 'OFF'
        USER_LIB = $ProjectDirectory
        HELP_FILE_DIR = $compilerDirectory
        MEGA_LPM = ((@('max2lib\prim', 'max2lib\mf', 'max2lib\mega_lpm', 'max2inc', 'max2lib\edif') |
            ForEach-Object { Join-Path $compilerDirectory $_ }) -join ';') + ';'
    }
    $encoding = [System.Text.Encoding]::GetEncoding(28591)
    $sourceIni = Join-Path $compilerDirectory 'maxplus2.ini'
    $iniLines = New-Object 'System.Collections.Generic.List[string]'
    $section = ''
    $foundSystem = $false
    $written = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($sourceIni, $encoding)) {
        if ($line -match '^\[([^\]]+)\]') {
            if ($section -eq 'SYSTEM') {
                foreach ($key in $updates.Keys) {
                    if (-not $written.ContainsKey($key)) { $iniLines.Add("$key=$($updates[$key])") }
                }
            }
            $section = $Matches[1]
            if ($section -eq 'SYSTEM') { $foundSystem = $true }
        }
        if ($section -eq 'SYSTEM' -and $line -match '^\s*([^=]+)=') {
            $key = $Matches[1].Trim()
            if ($key -match '^PROJECT_NAME[0-9]+$') { continue }
            if ($updates.ContainsKey($key)) {
                if (-not $written.ContainsKey($key)) {
                    $iniLines.Add("$key=$($updates[$key])")
                    $written[$key] = $true
                }
                continue
            }
        }
        $iniLines.Add($line)
    }
    if ($section -eq 'SYSTEM') {
        foreach ($key in $updates.Keys) {
            if (-not $written.ContainsKey($key)) { $iniLines.Add("$key=$($updates[$key])") }
        }
    }
    if (-not $foundSystem) {
        throw "SYSTEM section was not found in compiler INI: $sourceIni"
    }
    [System.IO.File]::WriteAllLines((Join-Path $privateRoot 'ini\maxplus2.ini'), $iniLines, $encoding)

    return @{
        MAXPLUS2_INI = Join-Path $privateRoot 'ini'
        TEMP = Join-Path $privateRoot 'tmp'
        TMP = Join-Path $privateRoot 'tmp'
    }
}

$resultAcx = $null
$buildStarted = $false
try {
    $repositoryRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
    if ([string]::IsNullOrWhiteSpace($TransTtfPath)) {
        $TransTtfPath = Join-Path $repositoryRoot 'bin\transttf.exe'
    }
    $sourceDirectory = Join-Path $repositoryRoot 'net_list'
    $buildRoot = Join-Path $repositoryRoot 'Build'
    $workDirectory = [System.IO.Path]::GetFullPath((Join-Path $buildRoot 'scroll'))
    $resultAcx = Join-Path $buildRoot 'scroll.acx'

    # Check tools and inputs before clearing the previous build.
    foreach ($requiredFile in @((Join-Path $sourceDirectory 'scroll.tdf'),
        (Join-Path $sourceDirectory 'scroll.acf'), $MaxPlusPath, $TransTtfPath)) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "Required file not found: $requiredFile"
        }
    }
    $MaxPlusPath = (Resolve-Path -LiteralPath $MaxPlusPath).ProviderPath
    $TransTtfPath = (Resolve-Path -LiteralPath $TransTtfPath).ProviderPath
    $compilerIni = Join-Path (Split-Path -Parent $MaxPlusPath) 'maxplus2.ini'
    if (-not (Test-Path -LiteralPath $compilerIni -PathType Leaf)) {
        throw "Compiler INI not found: $compilerIni"
    }

    # MAX+PLUS II requires the declared top-level name to match scroll.tdf.
    $tdfText = Get-Content -LiteralPath (Join-Path $sourceDirectory 'scroll.tdf') -Raw
    $acfText = Get-Content -LiteralPath (Join-Path $sourceDirectory 'scroll.acf') -Raw
    if ($tdfText -notmatch '(?im)^\s*SUBDESIGN\s+scroll\b') {
        throw 'scroll.tdf must declare SUBDESIGN scroll. Save the source file before building.'
    }
    if ($acfText -notmatch '(?im)^\s*CHIP\s+scroll\b') {
        throw 'scroll.acf must declare CHIP scroll. Save the source file before building.'
    }

    # Refuse junctions/symlinks so cleanup cannot reach outside Build\scroll.
    $expectedParent = [System.IO.Path]::GetFullPath($buildRoot)
    if ([System.IO.Path]::GetDirectoryName($workDirectory) -ine $expectedParent -or
        -not $workDirectory.StartsWith($repositoryRoot.TrimEnd('\') + '\',
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe build directory: $workDirectory"
    }
    foreach ($directory in @($buildRoot, $workDirectory)) {
        if (Test-Path -LiteralPath $directory) {
            $item = Get-Item -LiteralPath $directory -Force
            if (-not $item.PSIsContainer -or
                ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw "Build path must be a regular directory: $directory"
            }
        }
    }
    if (Test-Path -LiteralPath $workDirectory) {
        $linkedItems = @(Get-ChildItem -LiteralPath $workDirectory -Force -Recurse |
            Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint })
        if ($linkedItems.Count -gt 0) {
            throw "Build directory contains a junction or symlink: $($linkedItems[0].FullName)"
        }
    }

    Write-Host '=== SCROLL / ACEX build ==='
    Write-Host "Sources      : $sourceDirectory"
    Write-Host "Build folder : $workDirectory"
    Write-Host '=== Cleaning Build\scroll and copying net_list ==='
    if (Test-Path -LiteralPath $workDirectory) {
        Remove-Item -LiteralPath $workDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $workDirectory -Force | Out-Null
    $buildStarted = $true
    if (Test-Path -LiteralPath $resultAcx) {
        Remove-Item -LiteralPath $resultAcx -Force
    }
    Get-ChildItem -LiteralPath $sourceDirectory -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $workDirectory -Recurse -Force
    }

    $compilerEnvironment = New-CompilerEnvironment -CompilerPath $MaxPlusPath -ProjectDirectory $workDirectory
    Write-Host "Compiler INI : $($compilerEnvironment.MAXPLUS2_INI)\maxplus2.ini"
    Write-Host '=== MAX+PLUS II: compiling scroll in Build\scroll ==='
    $compiler = Invoke-BuildTool -FilePath $MaxPlusPath -Arguments @('-c', 'scroll') `
        -WorkingDirectory $workDirectory -LogName 'compile_msg' -EnvironmentOverrides $compilerEnvironment
    $successfulMessage = @($compiler.OutputLines |
        Where-Object { $_ -like '*Project compilation was successful*' }).Count -gt 0
    $compilerErrors = @($compiler.OutputLines | Where-Object { $_ -match '(?i)^\s*Error:' })
    if ($compiler.ExitCode -ne 0 -or -not $successfulMessage -or $compilerErrors.Count -gt 0) {
        throw "MAX+PLUS II compilation failed (exit code $($compiler.ExitCode)). See $workDirectory\compile_msg.txt"
    }

    $ttfFile = Join-Path $workDirectory 'scroll.ttf'
    if (-not (Test-Path -LiteralPath $ttfFile -PathType Leaf) -or
        (Get-Item -LiteralPath $ttfFile).Length -eq 0) {
        throw "Compiler reported success but scroll.ttf is missing or empty: $ttfFile"
    }

    Write-Host '=== TransTTF: scroll.ttf -> Build\scroll.acx ==='
    $conversion = Invoke-BuildTool -FilePath $TransTtfPath `
        -Arguments @('scroll.ttf', '..\scroll.acx') `
        -WorkingDirectory $workDirectory -LogName 'transttf_msg'
    if ($conversion.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $resultAcx -PathType Leaf) -or
        (Get-Item -LiteralPath $resultAcx).Length -eq 0) {
        throw "TransTTF failed (exit code $($conversion.ExitCode)); scroll.acx is missing, empty or incomplete."
    }

    $reportFile = Join-Path $workDirectory 'scroll.rpt'
    if (Test-Path -LiteralPath $reportFile -PathType Leaf) {
        $reportText = Get-Content -LiteralPath $reportFile -Raw -Encoding Default
        Write-DeviceSummary -ReportText $reportText
        Write-TimingSummary -ReportText $reportText
    }
    else {
        Write-Warning "Resource and fmax report was not created: $reportFile"
    }
    $compiler.OutputLines | Where-Object { $_ -match '(?i)fmax' } |
        Select-Object -Unique | ForEach-Object { Write-Host $_ }

    Write-Host "=== BUILD OK: $resultAcx ===" -ForegroundColor Green
    exit 0
}
catch {
    if ($buildStarted -and (Test-Path -LiteralPath $resultAcx -PathType Leaf)) {
        Remove-Item -LiteralPath $resultAcx -Force -ErrorAction SilentlyContinue
    }
    Write-Host ''
    Write-Host '!!!!!!!!!!!!!!!!!!!! BUILD FAILED !!!!!!!!!!!!!!!!!!!!' -ForegroundColor White -BackgroundColor DarkRed
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' -ForegroundColor White -BackgroundColor DarkRed
    exit 1
}
