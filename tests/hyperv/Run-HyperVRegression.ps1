#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]$Python,
    [string]$MultipassPath,
    [string]$VmA = "wgtcp-a",
    [string]$VmB = "wgtcp-b",
    [switch]$KeepGoing
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-WorkingPython {
    param([Parameter(Mandatory)][string]$CommandName)

    try {
        $candidate = Get-Command -Name $CommandName -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
        $executable = $candidate.Source
        $probeArguments = @(if ([IO.Path]::GetFileName($executable) -ieq "py.exe") {
            "-3"
            "--version"
        } else {
            "--version"
        })
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $executable
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        foreach ($argument in $probeArguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
        $probe = [System.Diagnostics.Process]::new()
        $probe.StartInfo = $startInfo
        try {
            [void]$probe.Start()
            $stdoutTask = $probe.StandardOutput.ReadToEndAsync()
            $stderrTask = $probe.StandardError.ReadToEndAsync()
            if (-not $probe.WaitForExit(10000)) {
                $probe.Kill($true)
                $probe.WaitForExit()
                return $null
            }
            [void]$stdoutTask.GetAwaiter().GetResult()
            [void]$stderrTask.GetAwaiter().GetResult()
            if ($probe.ExitCode -eq 0) { return $executable }
        } finally {
            $probe.Dispose()
        }
    } catch {
        # Try the next candidate when discovery or execution fails.
    }

    return $null
}

if ($Python) {
    $requestedPython = $Python
    $Python = Resolve-WorkingPython -CommandName $requestedPython
    if (-not $Python) {
        throw "The Python interpreter specified by -Python ('$requestedPython') could not run successfully."
    }
} else {
    foreach ($candidateName in @("python.exe", "py.exe")) {
        $Python = Resolve-WorkingPython -CommandName $candidateName
        if ($Python) { break }
    }
    if (-not $Python) {
        throw "Python 3 was not found. Tried 'python.exe --version' and 'py.exe -3 --version'."
    }
}

$arguments = @(
    (Join-Path $PSScriptRoot "regression.py"),
    "--vm-a", $VmA,
    "--vm-b", $VmB,
    "--results-dir", (Join-Path $PSScriptRoot "results")
)
if ([IO.Path]::GetFileName($Python) -ieq "py.exe") {
    $arguments = @("-3") + $arguments
}
if ($MultipassPath) { $arguments += @("--multipass", $MultipassPath) }
if ($KeepGoing) { $arguments += "--keep-going" }

& $Python @arguments
if ($LASTEXITCODE -ne 0) { throw "Hyper-V regression suite failed with exit code $LASTEXITCODE." }
