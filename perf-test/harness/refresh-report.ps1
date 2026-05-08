<#
.SYNOPSIS
    Periodically regenerate REPORT.md from cell.json files and push to git.

.DESCRIPTION
    Runs in a loop: aggregate -> regenerate REPORT.md -> if changed, commit & push.
    Intended to run alongside an in-flight matrix campaign so REPORT.md fills in
    as cells complete.

.PARAMETER ResultsDir
    Path to the campaign results dir containing cells/ subdir.
    e.g. C:\Users\...\Temp\wgtcpbase-perf\results\baseline-1.0.0-p2p

.PARAMETER RepoRoot
    Path to local clone of the WireguardTCP repo.
    e.g. C:\Users\...\Temp\wgtcpbase-sync

.PARAMETER IntervalSeconds
    Seconds between regeneration cycles. Default 600 (10 min).

.PARAMETER MaxIterations
    Stop after N cycles. 0 = run forever. Default 0.

.PARAMETER NoPush
    Regenerate + commit locally but do not push.

.EXAMPLE
    .\refresh-report.ps1 -ResultsDir $env:TEMP\wgtcpbase-perf\results\baseline-1.0.0-p2p `
                         -RepoRoot   $env:TEMP\wgtcpbase-sync `
                         -IntervalSeconds 600

.NOTES
    Assumes harness/summary-report.py is already in the repo at
    $RepoRoot\perf-test\harness\summary-report.py and writes to
    $RepoRoot\perf-test\REPORT.md.

    Requires git credentials cached for `git push origin main` to work
    non-interactively.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ResultsDir,
    [Parameter(Mandatory)] [string] $RepoRoot,
    [int] $IntervalSeconds = 600,
    [int] $MaxIterations = 0,
    [switch] $NoPush
)

$ErrorActionPreference = 'Stop'
$reportPath  = Join-Path $RepoRoot 'perf-test\REPORT.md'
$matrixSrc   = Join-Path $ResultsDir 'matrix.csv'
$matrixDst   = Join-Path $RepoRoot 'perf-test\results\baseline-1.0.0-p2p\matrix.csv'
$summaryPy   = Join-Path $RepoRoot 'perf-test\harness\summary-report.py'
$aggregatePy = Join-Path $RepoRoot 'perf-test\harness\aggregate.py'

if (-not (Test-Path $summaryPy))   { throw "summary-report.py not found at $summaryPy" }
if (-not (Test-Path $aggregatePy)) { throw "aggregate.py not found at $aggregatePy" }
if (-not (Test-Path $ResultsDir))  { throw "results dir not found: $ResultsDir" }

$iter = 0
while ($true) {
    $iter++
    $ts = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
    Write-Host "[$ts] iter $iter — refreshing report" -ForegroundColor Cyan

    # Count cells captured (for commit message context)
    $cellCount = (Get-ChildItem (Join-Path $ResultsDir 'cells') -Recurse -Filter cell.json -ErrorAction SilentlyContinue).Count

    # Regenerate matrix.csv (best-effort; aggregate.py prints to stderr on warnings)
    try {
        python $aggregatePy $ResultsDir -o $matrixSrc 2>&1 | Out-Null
        if (Test-Path $matrixSrc) {
            (Get-Content $matrixSrc -Raw).Replace('wireguard-tcp-base','wireguard-tcp-base') |
                Set-Content $matrixDst -NoNewline
        }
    } catch {
        Write-Warning "aggregate failed: $_"
    }

    # Regenerate REPORT.md
    try {
        python $summaryPy $ResultsDir $reportPath 2>&1 | Out-Null
    } catch {
        Write-Warning "summary-report failed: $_"
    }

    # Check if anything changed in the repo
    Push-Location $RepoRoot
    try {
        $changed = git status --porcelain perf-test/REPORT.md perf-test/results/baseline-1.0.0-p2p/matrix.csv
        if ($changed) {
            Write-Host "  changes detected — committing ($cellCount cells captured)" -ForegroundColor Green
            git add perf-test/REPORT.md perf-test/results/baseline-1.0.0-p2p/matrix.csv 2>&1 | Out-Null
            $msg = "perf-test: refresh REPORT.md ($cellCount cells, iter $iter @ $ts)`n`nCo-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
            git -c user.name="Dragos Ruiu" -c user.email="dragosruiu@users.noreply.github.com" commit -m $msg 2>&1 | Out-Null
            if (-not $NoPush) {
                git push origin main 2>&1 | Out-Null
                Write-Host "  pushed" -ForegroundColor Green
            }
        } else {
            Write-Host "  no changes" -ForegroundColor DarkGray
        }
    } finally {
        Pop-Location
    }

    if ($MaxIterations -gt 0 -and $iter -ge $MaxIterations) {
        Write-Host "reached MaxIterations=$MaxIterations, stopping"
        break
    }
    Write-Host "  sleeping ${IntervalSeconds}s..."
    Start-Sleep -Seconds $IntervalSeconds
}
