#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MultipassMsi,

    [Parameter(Mandatory = $true)]
    [string]$StatePath,

    [string]$HyperVUser = "$env:USERDOMAIN\$env:USERNAME",

    [string]$ExpectedMsiSha256 = "F5BFF63D13FB1377A72B8DD6D277BBDD3369B1F278F4C85D2C8427A2E7D38D39",

    [string]$ExpectedSignerThumbprint = "A5A11C3D23616DF6C9A3E1A3D1C3E12E56ACD607"
)

$ErrorActionPreference = "Stop"
$restartNeeded = $false

if (-not (Test-Path -LiteralPath $MultipassMsi -PathType Leaf)) {
    throw "Multipass MSI not found: $MultipassMsi"
}

$actualMsiHash = (Get-FileHash -LiteralPath $MultipassMsi -Algorithm SHA256).Hash
if ($actualMsiHash -ne $ExpectedMsiSha256) {
    throw "Multipass MSI SHA-256 mismatch. Expected $ExpectedMsiSha256, got $actualMsiHash."
}
$signature = Get-AuthenticodeSignature -LiteralPath $MultipassMsi
if ($signature.Status -ne "Valid" -or -not $signature.SignerCertificate) {
    throw "Multipass MSI does not have a valid Authenticode signature: $($signature.StatusMessage)"
}
if ($signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=CANONICAL GROUP LIMITED(,|$)') {
    throw "Unexpected Multipass MSI signer: $($signature.SignerCertificate.Subject)"
}
if ($signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
    throw "Multipass MSI signer thumbprint mismatch. Expected $ExpectedSignerThumbprint, got $($signature.SignerCertificate.Thumbprint)."
}

$stateDirectory = Split-Path -Parent $StatePath
if ($stateDirectory) {
    New-Item -ItemType Directory -Force $stateDirectory | Out-Null
}

$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($feature.State -ne "Enabled") {
    $featureResult = Enable-WindowsOptionalFeature `
        -Online `
        -FeatureName Microsoft-Hyper-V-All `
        -All `
        -NoRestart
    $restartNeeded = $restartNeeded -or $featureResult.RestartNeeded
}

$multipass = Get-Command multipass.exe -ErrorAction SilentlyContinue
if (-not $multipass) {
    $msiLog = [IO.Path]::ChangeExtension($StatePath, ".msi.log")
    $arguments = @(
        "/i"
        ('"{0}"' -f $MultipassMsi)
        "/qn"
        "/norestart"
        "/l*v"
        ('"{0}"' -f $msiLog)
    )
    $installer = Start-Process `
        -FilePath msiexec.exe `
        -ArgumentList $arguments `
        -Wait `
        -PassThru
    if ($installer.ExitCode -notin 0, 1641, 3010) {
        throw "Multipass MSI failed with exit code $($installer.ExitCode). See $msiLog"
    }
    $restartNeeded = $restartNeeded -or ($installer.ExitCode -in 1641, 3010)
}

$member = Get-LocalGroupMember `
    -Group "Hyper-V Administrators" `
    -Member $HyperVUser `
    -ErrorAction SilentlyContinue
if (-not $member) {
    Add-LocalGroupMember -Group "Hyper-V Administrators" -Member $HyperVUser
}

$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
$multipassPath = @(
    "$env:ProgramFiles\Multipass\bin\multipass.exe"
    "$env:ProgramFiles\Multipass\multipass.exe"
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

$state = [ordered]@{
    Timestamp = (Get-Date).ToString("o")
    HyperVFeature = [string]$feature.State
    HyperVUser = $HyperVUser
    MultipassPath = $multipassPath
    MultipassMsiSha256 = $actualMsiHash
    MultipassSigner = $signature.SignerCertificate.Subject
    MultipassSignerThumbprint = $signature.SignerCertificate.Thumbprint
    RestartNeeded = $restartNeeded
}

$state | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding utf8
$state | Format-List
