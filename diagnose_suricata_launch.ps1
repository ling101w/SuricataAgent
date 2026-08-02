[CmdletBinding()]
param(
    [ValidateRange(1, 50)]
    [int]$Runs = 5,

    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 10,

    [string]$SuricataBin = "",

    [string]$SuricataConfig = ""
)

$ErrorActionPreference = "Stop"
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$runtimeRoot = Join-Path $projectDir ".runtime\launch-diagnostics"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
$outputDir = Join-Path $runtimeRoot $timestamp
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8NoBom {
    param([string]$Path, [string]$Value)

    [System.IO.File]::WriteAllText($Path, $Value, $utf8NoBom)
}

function ConvertTo-ProcessArgument {
    param([string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes += 1
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * ($backslashes * 2 + 1)))
            [void]$builder.Append('"')
        }
        else {
            if ($backslashes) {
                [void]$builder.Append(('\' * $backslashes))
            }
            [void]$builder.Append($character)
        }
        $backslashes = 0
    }
    if ($backslashes) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-DiagnosticProcess {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$RunDirectory,
        [int]$Timeout,
        [string[]]$ExtraPath = @()
    )

    New-Item -ItemType Directory -Force -Path $RunDirectory | Out-Null
    $stdoutPath = Join-Path $RunDirectory "stdout.log"
    $stderrPath = Join-Path $RunDirectory "stderr.log"
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = ($Arguments | ForEach-Object {
        ConvertTo-ProcessArgument ([string]$_)
    }) -join " "
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $startInfo.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    foreach ($secretName in @("DEEPSEEK_API_KEY", "OPENAI_API_KEY")) {
        if ($startInfo.EnvironmentVariables.ContainsKey($secretName)) {
            $startInfo.EnvironmentVariables.Remove($secretName)
        }
    }
    if ($ExtraPath.Count -gt 0) {
        $currentPath = $startInfo.EnvironmentVariables["PATH"]
        $startInfo.EnvironmentVariables["PATH"] = (
            @($ExtraPath) + @($currentPath)
        ) -join [System.IO.Path]::PathSeparator
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $completed = $process.WaitForExit($Timeout * 1000)
    if (-not $completed) {
        try { $process.Kill() } catch { }
        [void]$process.WaitForExit(5000)
    }
    else {
        $process.WaitForExit()
    }
    $timer.Stop()
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    Write-Utf8NoBom $stdoutPath $stdout
    Write-Utf8NoBom $stderrPath $stderr
    $exitCode = if ($completed) { $process.ExitCode } else { $null }
    $process.Dispose()

    return [pscustomobject]@{
        passed = $completed -and $exitCode -eq 0
        timed_out = -not $completed
        exit_code = $exitCode
        elapsed_ms = $timer.ElapsedMilliseconds
        stdout = $stdoutPath
        stderr = $stderrPath
    }
}

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

if (-not $SuricataBin) {
    $SuricataBin = if ($env:SURICATA_BIN) {
        $env:SURICATA_BIN
    }
    else {
        Join-Path $projectDir "suricata\suricata.exe"
    }
}
if (-not $SuricataConfig) {
    $SuricataConfig = if ($env:SURICATA_CONFIG) {
        $env:SURICATA_CONFIG
    }
    else {
        Join-Path $projectDir "suricata\suricata.yaml"
    }
}

$suricataExe = (Resolve-Path -LiteralPath $SuricataBin).Path
$configPath = (Resolve-Path -LiteralPath $SuricataConfig).Path
$configDir = Split-Path -Parent $configPath
$rulePath = Join-Path $outputDir "diagnostic.rules"
Write-Utf8NoBom $rulePath (
    'alert http any any -> any any (msg:"launch diagnostic"; flow:to_server; ' +
    'http.uri; content:"/__suricata_launch_diagnostic__"; sid:4294000001; rev:1;)' +
    [Environment]::NewLine
)

$pathEntries = @((Split-Path -Parent $suricataExe))
$npcapDir = Join-Path $env:SystemRoot "System32\Npcap"
if (Test-Path -LiteralPath (Join-Path $npcapDir "wpcap.dll")) {
    $pathEntries += $npcapDir
}

$results = @()
Write-Output "Running PowerShell baseline ($Runs runs)..."
for ($index = 1; $index -le $Runs; $index += 1) {
    $runDir = Join-Path $outputDir ("powershell-{0:D2}" -f $index)
    $logDir = Join-Path $runDir "suricata-logs"
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $result = Invoke-DiagnosticProcess `
        -FilePath $suricataExe `
        -Arguments @("-T", "-c", $configPath, "-S", $rulePath, "-l", $logDir) `
        -WorkingDirectory $configDir `
        -RunDirectory $runDir `
        -Timeout $TimeoutSeconds `
        -ExtraPath $pathEntries
    $record = [pscustomobject]@{
        mode = "powershell"
        run = $index
        passed = $result.passed
        timed_out = $result.timed_out
        exit_code = $result.exit_code
        elapsed_ms = $result.elapsed_ms
        stdout = $result.stdout
        stderr = $result.stderr
    }
    $results += $record
    $label = if ($record.passed) { "PASS" } elseif ($record.timed_out) { "TIMEOUT" } else { "FAIL" }
    Write-Output ("  {0}/{1}: {2} ({3} ms)" -f $index, $Runs, $label, $record.elapsed_ms)
}

$pythonCommand = Get-Command python -ErrorAction Stop
$helperPath = Join-Path $outputDir "python_app_launch.py"
$helperSource = @'
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

project_dir = Path(sys.argv[1]).resolve()
timeout = int(sys.argv[2])
command = sys.argv[3:]
sys.path.insert(0, str(project_dir))

from validate_rules import run_command

started = time.perf_counter()
try:
    process = run_command(command, timeout=timeout)
except subprocess.TimeoutExpired:
    payload = {"passed": False, "timed_out": True, "exit_code": None}
    exit_code = 124
except Exception as exc:
    payload = {
        "passed": False,
        "timed_out": False,
        "exit_code": None,
        "error": str(exc)[:2000],
    }
    exit_code = 1
else:
    payload = {
        "passed": process.returncode == 0,
        "timed_out": False,
        "exit_code": process.returncode,
        "suricata_stdout": process.stdout[-4000:],
        "suricata_stderr": process.stderr[-4000:],
    }
    exit_code = 0 if process.returncode == 0 else 1
payload["elapsed_ms"] = round((time.perf_counter() - started) * 1000)
print(json.dumps(payload, ensure_ascii=False))
raise SystemExit(exit_code)
'@
Write-Utf8NoBom $helperPath $helperSource

Write-Output "Running Python app-style launch ($Runs runs)..."
for ($index = 1; $index -le $Runs; $index += 1) {
    $runDir = Join-Path $outputDir ("python-{0:D2}" -f $index)
    $logDir = Join-Path $runDir "suricata-logs"
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $result = Invoke-DiagnosticProcess `
        -FilePath $pythonCommand.Source `
        -Arguments @(
            $helperPath,
            $projectDir,
            [string]$TimeoutSeconds,
            $suricataExe,
            "-T", "-c", $configPath, "-S", $rulePath, "-l", $logDir
        ) `
        -WorkingDirectory $projectDir `
        -RunDirectory $runDir `
        -Timeout ($TimeoutSeconds + 5)
    $record = [pscustomobject]@{
        mode = "python"
        run = $index
        passed = $result.passed
        timed_out = $result.timed_out
        exit_code = $result.exit_code
        elapsed_ms = $result.elapsed_ms
        stdout = $result.stdout
        stderr = $result.stderr
    }
    $results += $record
    $label = if ($record.passed) { "PASS" } elseif ($record.timed_out) { "TIMEOUT" } else { "FAIL" }
    Write-Output ("  {0}/{1}: {2} ({3} ms)" -f $index, $Runs, $label, $record.elapsed_ms)
}

$nativeOk = @($results | Where-Object { $_.mode -eq "powershell" -and $_.passed }).Count -eq $Runs
$pythonOk = @($results | Where-Object { $_.mode -eq "python" -and $_.passed }).Count -eq $Runs
$classification = if ($nativeOk -and $pythonOk) {
    "NATIVE_OK"
}
elseif ($nativeOk) {
    "PYTHON_CHILD_UNSTABLE"
}
else {
    "SURICATA_RUNTIME_UNSTABLE"
}
$summaryPath = Join-Path $outputDir "summary.json"
$summary = [ordered]@{
    classification = $classification
    runs = $Runs
    timeout_seconds = $TimeoutSeconds
    suricata_bin = $suricataExe
    suricata_config = $configPath
    results = $results
}
Write-Utf8NoBom $summaryPath (($summary | ConvertTo-Json -Depth 8) + [Environment]::NewLine)

Write-Output ("Result: " + $classification)
Write-Output ("Summary: " + $summaryPath)
if ($classification -ne "NATIVE_OK") {
    exit 1
}
