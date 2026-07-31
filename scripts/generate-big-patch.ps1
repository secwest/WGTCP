#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BaseTree,

    [string]$OutputPath = (Join-Path $PSScriptRoot "..\BIG-WireguardTCP-Patch"),

    [string]$TargetCommit = "HEAD"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseTree = (Resolve-Path -LiteralPath $BaseTree).Path
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

foreach ($path in @("kernel", "include/uapi/linux/wireguard.h", "tools")) {
    if (-not (Test-Path -LiteralPath (Join-Path $BaseTree $path))) {
        throw "Patch baseline is missing $path"
    }
}

$target = git -C (Join-Path $PSScriptRoot "..") rev-parse $TargetCommit
if ($LASTEXITCODE -ne 0) { throw "Could not resolve target commit $TargetCommit" }

$untracked = @(git -C $BaseTree ls-files --others --exclude-standard)
if ($LASTEXITCODE -ne 0) { throw "Could not enumerate new patch files" }
if ($untracked.Count -gt 0) {
    git -C $BaseTree add --intent-to-add -- $untracked
    if ($LASTEXITCODE -ne 0) { throw "Could not include new patch files" }
}

$diff = git -C $BaseTree -c core.safecrlf=false diff --binary --full-index --no-ext-diff
if ($LASTEXITCODE -ne 0) { throw "Could not generate patch delta" }

$header = @"
BIG WireGuard TCP implementation patch

Kernel baseline: Linux v6.8 (90d1f30371ae3337beb01666b226320728d35c70)
Tools baseline: wireguard-tools a998407747005ea7e4e0258d96f105c97241e1d3
Target repository: https://github.com/secwest/WireguardTCP.git
Target source commit: $target

This patch contains only the kernel module, UAPI, and wg/wg-quick changes
needed to build and run WireguardTCP. Documentation, performance campaigns,
test harnesses, result archives, website files, and release artifacts are
excluded. Upstream kernel crypto, SIMD, and architecture assembly are not
modified by this patch.

Prepare the baseline from clean official checkouts:

    git clone https://github.com/torvalds/linux.git linux
    git -C linux checkout 90d1f30371ae3337beb01666b226320728d35c70
    git clone https://github.com/WireGuard/wireguard-tools.git wireguard-tools
    git -C wireguard-tools checkout a998407747005ea7e4e0258d96f105c97241e1d3
    mkdir WireguardTCP-patch-base
    cp -a linux/drivers/net/wireguard WireguardTCP-patch-base/kernel
    mkdir -p WireguardTCP-patch-base/include/uapi/linux
    cp linux/include/uapi/linux/wireguard.h WireguardTCP-patch-base/include/uapi/linux/
    cp -a wireguard-tools/src WireguardTCP-patch-base/tools

Apply and build on Ubuntu 24.04 with matching kernel headers installed:

    cd WireguardTCP-patch-base
    git apply --binary /path/to/BIG-WireguardTCP-Patch
    make -C tools -j`$(nproc)
    make -C /lib/modules/`$(uname -r)/build M=`$PWD/kernel CONFIG_WIREGUARD=m -j`$(nproc) modules

"@

$content = $header.Replace("`r`n", "`n") + ($diff -join "`n") + "`n"
[IO.File]::WriteAllText($OutputPath, $content, [Text.UTF8Encoding]::new($false))
Write-Output "Wrote $OutputPath ($($content.Length) bytes)"
