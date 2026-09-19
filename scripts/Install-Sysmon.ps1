#Requires -RunAsAdministrator
param(
  [Parameter(Mandatory=$true)][string]$SysmonPath,
  [switch]$UpdateExisting,
  [switch]$AcceptLicense
)
$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $SysmonPath).Path
$signature = Get-AuthenticodeSignature -LiteralPath $resolved
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Use a valid Microsoft-signed Sysmon binary downloaded from Microsoft Sysinternals.' }
$config = Join-Path $PSScriptRoot 'sysmon-config.xml'
$existing = @(Get-Service -Name Sysmon,Sysmon64,Sysmon64a -ErrorAction SilentlyContinue)
if ($existing.Count -gt 0) {
  if (!$UpdateExisting) { throw 'Sysmon is already installed. Review and back up your existing configuration before explicitly using -UpdateExisting. Do not replace organizational monitoring policies.' }
  & $resolved -c $config
} else {
  # Without -AcceptLicense, Sysmon presents its own license agreement.
  if ($AcceptLicense) { & $resolved -accepteula -i $config } else { & $resolved -i $config }
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon returned exit code $LASTEXITCODE." }
Write-Host 'Sysmon configuration applied. Refresh Device readiness in Observe.'
