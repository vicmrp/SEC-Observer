$ErrorActionPreference = 'Stop'
$pidFile = Join-Path $env:LOCALAPPDATA 'Observe\launcher.json'
if (!(Test-Path -LiteralPath $pidFile)) { Write-Host 'No launcher-managed Observe process was found.'; exit }
$saved = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
$process = Get-Process -Id $saved.pid -ErrorAction SilentlyContinue
if (!$process) { Write-Host 'Observe is already stopped.'; exit }
if ($process.Path -ne $saved.runtime -or $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $saved.started) { throw 'The saved process no longer matches Observe. Refusing to stop another application.' }
# Active observations recover as interrupted. Finish a capture in the UI before closing.
Stop-Process -Id $process.Id
Write-Host 'Observe stopped. Saved observations remain on this device.'
