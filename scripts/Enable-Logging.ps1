#Requires -RunAsAdministrator
param([switch]$Restore)
$ErrorActionPreference = 'Stop'
$backupPath = Join-Path $env:ProgramData 'Observe\logging-policy-backup.json'
$policies = @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging')
if ($Restore) {
  if (!(Test-Path -LiteralPath $backupPath)) { throw 'No saved Observe policy backup was found.' }
  $backup = Get-Content -LiteralPath $backupPath -Raw | ConvertFrom-Json
  foreach ($entry in $backup.policies) {
    if ($entry.existed) { Set-ItemProperty -LiteralPath $entry.path -Name EnableScriptBlockLogging -Value $entry.value -Type DWord }
    else { Remove-ItemProperty -LiteralPath $entry.path -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue }
  }
  Write-Host 'Previous Script Block Logging policy values restored. Open new PowerShell sessions to apply them.'
  exit
}
if (!(Test-Path -LiteralPath $backupPath)) {
  $previous = foreach ($policy in $policies) {
    $item = Get-ItemProperty -LiteralPath $policy -ErrorAction SilentlyContinue
    @{ path = $policy; existed = ($null -ne $item.EnableScriptBlockLogging); value = $item.EnableScriptBlockLogging }
  }
  New-Item -ItemType Directory -Path (Split-Path $backupPath) -Force | Out-Null
  @{ policies = @($previous); createdAt = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $backupPath -Encoding UTF8
}
foreach ($policy in $policies) {
  New-Item -Path $policy -Force | Out-Null
  New-ItemProperty -LiteralPath $policy -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null
}
Write-Host 'Script Block Logging enabled for Windows PowerShell and PowerShell 7.'
Write-Host 'Start new PowerShell sessions. Domain policy and PowerShell configuration files can affect effective settings.'
Write-Host 'The existing event channels must also be enabled. Observe shows channel status in Device readiness.'
Write-Host "Previous policy values saved to $backupPath. Restore using this script with -Restore."
Write-Host 'Script content may include secrets. Windows keeps these logs independently of Observe.'
