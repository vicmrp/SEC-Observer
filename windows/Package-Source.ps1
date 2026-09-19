$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$repository = Split-Path $PSScriptRoot -Parent
$destination = Join-Path $repository 'dist\Observe-Source.zip'
$files = @('README.md','LICENSE','SECURITY.md','package.json','.gitignore','server.mjs','gateway.mjs','Start-Observe.cmd','Stop-Observe.cmd') | ForEach-Object { Get-Item -LiteralPath (Join-Path $repository $_) }
foreach ($folder in @('src','public','scripts','test','windows')) {
  $files += Get-ChildItem -LiteralPath (Join-Path $repository $folder) -File -Recurse | Where-Object { $_.FullName -notmatch '[\\/](bin|obj|dashboard-previews)[\\/]' -and $_.Name -notmatch '\.json$|\.pdb$' }
}
$stream = [System.IO.File]::Create($destination)
$archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
try {
  foreach ($file in $files) {
    $relative = $file.FullName.Substring($repository.Length).TrimStart('\','/').Replace('\','/')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,$file.FullName,'Observe-Source/'+$relative,[System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
  }
} finally { $archive.Dispose(); $stream.Dispose() }
Write-Host "Source archive: $destination"
