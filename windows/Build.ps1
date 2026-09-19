param([string]$Configuration = 'Release', [string]$ReleaseName = 'Observe-Windows-0.12.1-beta-vibe-coded', [switch]$LiveTests)
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'Observe.Desktop\Observe.Desktop.csproj'
$repository = Split-Path $PSScriptRoot -Parent
if ($ReleaseName -notmatch '^[A-Za-z0-9._-]+$') { throw 'ReleaseName must be a folder name.' }
$destination = Join-Path $repository ('dist\'+$ReleaseName)
& dotnet build (Join-Path $PSScriptRoot 'Observe.CanaryMod\Observe.CanaryMod.csproj') -c Release
if ($LASTEXITCODE -ne 0) { throw 'Harmless canary mod build failed.' }
& dotnet publish $project -c $Configuration -r win-x64 --self-contained true -o $destination
if ($LASTEXITCODE -ne 0) { throw 'Native build failed.' }
$runtimeConfig = Get-Content (Join-Path $PSScriptRoot "Observe.Desktop\bin\$Configuration\net10.0-windows\win-x64\Observe.runtimeconfig.json") -Raw | ConvertFrom-Json
$frameworks = $runtimeConfig.runtimeOptions.includedFrameworks
$assets = Get-Content (Join-Path $PSScriptRoot 'Observe.Desktop\obj\project.assets.json') -Raw | ConvertFrom-Json
$packageRoots = @($assets.packageFolders.PSObject.Properties.Name)
$notices = Join-Path $destination 'licenses'
New-Item -ItemType Directory -Path $notices -Force | Out-Null
foreach ($framework in $frameworks) {
  $id = switch ($framework.name) { 'Microsoft.NETCore.App' { 'microsoft.netcore.app.runtime.win-x64' } 'Microsoft.WindowsDesktop.App' { 'microsoft.windowsdesktop.app.runtime.win-x64' } }
  if (!$id) { continue }
  $package = $null
  foreach ($packageRoot in $packageRoots) { $candidate = Join-Path $packageRoot "$id\$($framework.version)"; if (Test-Path -LiteralPath $candidate) { $package = $candidate; break } }
  if (!$package) { throw "Runtime license package not found for $id $($framework.version)." }
  $found = @(Get-ChildItem -LiteralPath $package -File | Where-Object Name -Match 'LICENSE|NOTICE')
  if ($found.Count -eq 0) { throw "Missing runtime license for $id." }
  foreach ($file in $found) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $notices "$id-$($file.Name)") -Force }
}
Copy-Item -LiteralPath (Join-Path $repository 'LICENSE') -Destination $destination -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $destination -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'UVM-Integration.md') -Destination $destination -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Observe.CanaryMod\README.md') -Destination (Join-Path $destination 'Harmless-Mod-Test.md') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'licenses\TraceEvent-LICENSE.txt') -Destination $notices -Force
$inventory = @()
foreach ($entry in $assets.libraries.PSObject.Properties) {
  if ($entry.Value.type -ne 'package') { continue }
  $package = $null
  foreach ($root in $packageRoots) { $candidate = Join-Path $root $entry.Value.path; if (Test-Path -LiteralPath $candidate) { $package=$candidate; break } }
  if (!$package) { throw "Missing dependency metadata: $($entry.Name)" }
  $prefix=$entry.Name.Replace('/','-')
  $spec=Get-ChildItem -LiteralPath $package -Filter '*.nuspec' | Select-Object -First 1
  Copy-Item -LiteralPath $spec.FullName -Destination (Join-Path $notices ($prefix+'.nuspec')) -Force
  [xml]$metadata=Get-Content -LiteralPath $spec.FullName -Raw
  $inventory += "$($entry.Name) - $($metadata.package.metadata.license.InnerText) - $($metadata.package.metadata.copyright)"
  foreach ($file in Get-ChildItem -LiteralPath $package -File -Recurse | Where-Object Name -Match '^(LICENSE|NOTICE|THIRD.PARTY)') {
    $relative=$file.FullName.Substring($package.Length).TrimStart('\','/').Replace('\','-').Replace('/','-')
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $notices ($prefix+'-'+$relative)) -Force
  }
}
$inventory | Set-Content -LiteralPath (Join-Path $notices 'NuGet-dependencies.txt') -Encoding utf8
$binary = Join-Path $destination 'Observe.exe'
Copy-Item -LiteralPath $binary -Destination (Join-Path $destination 'Observe-Setup.exe') -Force
$testResults = Join-Path $PSScriptRoot 'native-test-results.json'
$testProcess = Start-Process -FilePath $binary -ArgumentList @('--self-test',('"'+$testResults+'"')) -WindowStyle Hidden -Wait -PassThru
if ($testProcess.ExitCode -ne 0) { throw "Native self-tests failed. See $testResults" }
$tests = Get-Content -LiteralPath $testResults -Raw | ConvertFrom-Json
if ($tests.failed -ne 0 -or $tests.passed -lt 20) { throw 'Unexpected self-test result.' }
$featureResults = Join-Path $PSScriptRoot 'feature-test-results.json'
$featureProcess = Start-Process -FilePath $binary -ArgumentList @('--feature-test',('"'+$featureResults+'"')) -WindowStyle Hidden -PassThru
if (!$featureProcess.WaitForExit(60000)) { $featureProcess.Kill(); throw 'Feature tests timed out.' }
if ($featureProcess.ExitCode -ne 0) { throw "Feature tests failed. See $featureResults" }
$investigationResults = Join-Path $PSScriptRoot 'investigation-test-results.json'
$investigationProcess = Start-Process -FilePath $binary -ArgumentList @('--investigation-test',('"'+$investigationResults+'"')) -WindowStyle Hidden -Wait -PassThru
if ($investigationProcess.ExitCode -ne 0) { throw "Investigation tests failed. See $investigationResults" }
$observerResults = Join-Path $PSScriptRoot 'observer-test-results.json'
$observerProcess = Start-Process -FilePath $binary -ArgumentList @('--observer-test',('"'+$observerResults+'"')) -WindowStyle Hidden -Wait -PassThru
if ($observerProcess.ExitCode -ne 0) { throw "Observer tests failed. See $observerResults" }
$workspaceResults = Join-Path $PSScriptRoot 'workspace-test-results.json'
$workspaceProcess = Start-Process -FilePath $binary -ArgumentList @('--workspace-test',('"'+$workspaceResults+'"')) -WindowStyle Hidden -Wait -PassThru
if ($workspaceProcess.ExitCode -ne 0) { throw "Workspace tests failed. See $workspaceResults" }
$explorerResults = Join-Path $PSScriptRoot 'explorer-test-results.json'
$explorerProcess = Start-Process -FilePath $binary -ArgumentList @('--explorer-test',('"'+$explorerResults+'"')) -WindowStyle Hidden -Wait -PassThru
if ($explorerProcess.ExitCode -ne 0) { throw "Explorer tests failed. See $explorerResults" }
$canaryResults = Join-Path $PSScriptRoot 'canary-test-results.json'
$canaryProcess = Start-Process -FilePath $binary -ArgumentList @('--canary-test',('"'+$canaryResults+'"')) -WindowStyle Hidden -Wait -PassThru
if ($canaryProcess.ExitCode -ne 0) { throw "Canary tests failed. See $canaryResults" }
$bridgeResults = Join-Path $PSScriptRoot 'cities-mod-test-results.json'
$bridgeProcess = Start-Process -FilePath $binary -ArgumentList @('--cities-mod-test',('"'+$bridgeResults+'"')) -WindowStyle Hidden -Wait -PassThru
if ($bridgeProcess.ExitCode -ne 0) { throw "Cities II bridge tests failed. See $bridgeResults" }
$zip = Join-Path $repository ('dist\'+$ReleaseName+'.zip')
$hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
@("$hash  Observe.exe", "$hash  Observe-Setup.exe") | Set-Content -LiteralPath (Join-Path $destination 'SHA256.txt') -Encoding ascii
$smokeResults = Join-Path $PSScriptRoot 'native-ui-results.json'
$smokeProcess = Start-Process -FilePath $binary -ArgumentList @('--ui-smoke',('"'+$smokeResults+'"')) -WindowStyle Hidden -Wait -PassThru
if ($smokeProcess.ExitCode -ne 0) { throw "Native UI construction failed. See $smokeResults" }
if ($LiveTests) {
  foreach ($kind in @('live','ui-live','dashboard')) {
    $result = Join-Path $PSScriptRoot ('native-'+$kind+'-results.json')
    $check = Start-Process -FilePath $binary -ArgumentList @(('--'+$kind+'-test'),('"'+$result+'"')) -WindowStyle Hidden -PassThru
    if (!$check.WaitForExit(150000)) { $check.Kill(); throw "$kind test timed out." }
    if ($check.ExitCode -ne 0) { throw "$kind test failed. See $result" }
  }
}
Get-ChildItem -LiteralPath $destination -Filter *.pdb | Remove-Item -Force
Compress-Archive -LiteralPath $destination -DestinationPath $zip -Force
Write-Host "Built $binary"
Write-Host "Packaged $zip"
Write-Host "$($tests.passed) self-tests passed."
