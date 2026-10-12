param([Parameter(Mandatory=$true)][string]$Archive,[Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$root = [System.IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
$zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
try {
    $total = 0L
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName.Replace('\','/')
        if ($name.StartsWith('/') -or $name.Contains(':') -or $name -match '(^|/)\.\.(/|$)') { throw 'Unsafe archive path' }
        $path = [System.IO.Path]::GetFullPath((Join-Path $Destination $name))
        if (-not $path.StartsWith($root,[System.StringComparison]::OrdinalIgnoreCase)) { throw 'Archive path escapes destination' }
        $total += $entry.Length
        if ($total -gt 536870912) { throw 'Archive exceeds extraction limit' }
        if ($name.EndsWith('/')) { New-Item -ItemType Directory -Force -Path $path | Out-Null; continue }
        New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($path)) | Out-Null
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$path,$false)
    }
} finally { $zip.Dispose() }
