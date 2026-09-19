param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$appDirectory = Split-Path $PSScriptRoot -Parent
$runtimePath = Join-Path $appDirectory 'runtime\node.exe'
if (!(Test-Path -LiteralPath $runtimePath)) {
  $nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
  if (!$nodeCommand) { throw 'Node.js 22 or newer is required. Install it from https://nodejs.org or use the portable Observe package.' }
  $runtimePath = $nodeCommand.Source
}
$port = if ($env:PORT) { [int]$env:PORT } else { 4317 }
$stateDirectory = Join-Path $env:LOCALAPPDATA 'Observe'
New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
$pidFile = Join-Path $stateDirectory 'launcher.json'
$url = "http://127.0.0.1:$port"
if (Test-Path -LiteralPath $pidFile) {
  try {
    $saved = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
    $previous = Get-Process -Id $saved.pid -ErrorAction Stop
    if ($previous.Path -eq $saved.runtime -and $previous.StartTime.ToUniversalTime().Ticks.ToString() -eq $saved.started) { if (!$NoBrowser) { Start-Process $saved.url }; exit }
  } catch { }
}
$process = Start-Process -FilePath $runtimePath -ArgumentList @('"' + (Join-Path $appDirectory 'server.mjs') + '"') -WorkingDirectory $appDirectory -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $stateDirectory 'server.log') -RedirectStandardError (Join-Path $stateDirectory 'server-error.log')
$started = $process.StartTime.ToUniversalTime().Ticks.ToString()
for ($attempt = 0; $attempt -lt 30; $attempt++) {
  if ($process.HasExited) { throw "Observe did not start. See $stateDirectory\server-error.log. The port may already be in use." }
  try { $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 1; if ($response.StatusCode -eq 200) { break } } catch { Start-Sleep -Milliseconds 300 }
}
if (!$response -or $response.StatusCode -ne 200) { throw "Observe is still starting. Open $url or check $stateDirectory\server-error.log." }
@{ pid = $process.Id; runtime = $runtimePath; started = $started; url = $url } | ConvertTo-Json | Set-Content -LiteralPath $pidFile -Encoding UTF8
if (!$NoBrowser) { Start-Process $url }
Write-Host "Observe is ready at $url"
