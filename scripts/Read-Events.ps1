param(
  [ValidateSet('status','events')][string]$Mode = 'status',
  [string]$StartUtc,
  [string]$EndUtc,
  [string]$CursorsJson = '{}'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$channels = @('Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational')
$results = @()
$cursors = $CursorsJson | ConvertFrom-Json
foreach ($channel in $channels) {
  $item = [ordered]@{ channel = $channel; available = $false; enabled = $false; error = $null; events = @(); hasMore = $false; reset = $false }
  if ($Mode -eq 'status' -and $channel -eq 'Microsoft-Windows-Sysmon/Operational') {
    $service = Get-Service -Name Sysmon,Sysmon64,Sysmon64a -ErrorAction SilentlyContinue | Select-Object -First 1
    $item.serviceState = if ($service) { [string]$service.Status } else { 'Not installed' }
  }
  try {
    $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
    $item.available = $true
    $item.enabled = [bool]$log.IsEnabled
    if ($Mode -eq 'status') {
      $item.recordCount = $log.RecordCount
      $item.logMode = [string]$log.LogMode
      $item.maxBytes = $log.MaximumSizeInBytes
      $policy = if ($channel -eq 'PowerShellCore/Operational') { 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging' } else { 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' }
      if ($channel -ne 'Microsoft-Windows-Sysmon/Operational') {
        $machine = Get-ItemProperty -LiteralPath $policy -ErrorAction SilentlyContinue
        $userPolicy = $policy.Replace('HKLM:', 'HKCU:')
        $user = Get-ItemProperty -LiteralPath $userPolicy -ErrorAction SilentlyContinue
        $effective = if ($null -ne $machine.EnableScriptBlockLogging) { $machine.EnableScriptBlockLogging } else { $user.EnableScriptBlockLogging }
        $item.scriptBlockPolicy = ($effective -eq 1)
      }
    } elseif ($item.enabled) {
      $start = [DateTimeOffset]::Parse($StartUtc).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
      $end = [DateTimeOffset]::Parse($EndUtc).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
      $cursorProperty = $cursors.PSObject.Properties[$channel]
      [long]$cursor = if ($null -ne $cursorProperty) { $cursorProperty.Value } else { 0 }
      # Detect an obvious log clear / record ID reset instead of silently skipping new records.
      $newest = Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction SilentlyContinue
      if ($null -ne $newest -and $cursor -gt [long]$newest.RecordId) { $cursor = 0; $item.reset = $true }
      $idFilter = if ($channel -eq 'Microsoft-Windows-Sysmon/Operational') { '' } else { ' and (EventID=4103 or EventID=4104)' }
      $xpath = "*[System[TimeCreated[@SystemTime >= '$start' and @SystemTime <= '$end'] and EventRecordID > $cursor$idFilter]]"
      try { $found = @(Get-WinEvent -LogName $channel -FilterXPath $xpath -Oldest -MaxEvents 501 -ErrorAction Stop) }
      catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $found = @() } else { throw } }
      $item.hasMore = $found.Count -gt 500
      $item.events = @($found | Select-Object -First 500 | ForEach-Object {
        [xml]$xml = $_.ToXml()
        $data = [ordered]@{}
        foreach ($field in $xml.Event.EventData.Data) { if ($field.Name) { $data[[string]$field.Name] = [string]$field.'#text' } }
        [ordered]@{ channel = $channel; recordId = [string]$_.RecordId; eventId = [int]$_.Id; timestamp = $_.TimeCreated.ToUniversalTime().ToString('o'); data = $data }
      })
    }
  } catch { $item.error = $_.Exception.Message }
  $results += [pscustomobject]$item
}
ConvertTo-Json -InputObject @{ channels = @($results); checkedAt = [DateTime]::UtcNow.ToString('o') } -Depth 12 -Compress
