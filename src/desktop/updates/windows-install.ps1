param([Parameter(Mandatory=$true)][string]$Plan,[switch]$ApplyOnly)
$ErrorActionPreference = 'Stop'
$p = Get-Content -LiteralPath $Plan -Encoding UTF8 -Raw | ConvertFrom-Json
$shell = Join-Path $PSHOME 'powershell.exe'
$script = $PSCommandPath
if ($ApplyOnly) {
    $changed = @()
    try {
        if ((Test-Path -LiteralPath $p.incoming) -or (Test-Path -LiteralPath $p.backup)) { throw 'Update staging path already exists' }
        New-Item -ItemType Directory -Path $p.incoming | Out-Null
        New-Item -ItemType Directory -Path $p.backup | Out-Null
        foreach ($name in $p.files) {
            $source = Join-Path $p.staged $name
            if (-not (Test-Path -LiteralPath $source)) { continue }
            Copy-Item -LiteralPath $source -Destination (Join-Path $p.incoming $name) -Recurse
        }
        foreach ($name in $p.files) {
            $source = Join-Path $p.incoming $name
            if (-not (Test-Path -LiteralPath $source)) { continue }
            $target = Join-Path $p.destination $name
            $old = Join-Path $p.backup $name
            $hadOld = Test-Path -LiteralPath $target
            if ($hadOld) { Move-Item -LiteralPath $target -Destination $old }
            $changed += [pscustomobject]@{Name=$name;HadOld=$hadOld}
            Move-Item -LiteralPath $source -Destination $target
        }
        Remove-Item -LiteralPath $p.incoming -Recurse -Force
        exit 0
    } catch {
        $needsAdmin = $_.Exception -is [System.UnauthorizedAccessException]
        Write-Error $_ -ErrorAction Continue
        [array]::Reverse($changed)
        foreach ($item in $changed) {
            $target = Join-Path $p.destination $item.Name
            if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
            if ($item.HadOld) { Move-Item -LiteralPath (Join-Path $p.backup $item.Name) -Destination $target }
        }
        if (Test-Path -LiteralPath $p.incoming) { Remove-Item -LiteralPath $p.incoming -Recurse -Force }
        if (Test-Path -LiteralPath $p.backup) { Remove-Item -LiteralPath $p.backup -Recurse -Force }
        if ($needsAdmin) { exit 77 }
        exit 1
    }
}
[System.IO.File]::WriteAllText($p.ready,'ready')
$deadline = [DateTime]::UtcNow.AddMinutes(2)
while (Get-Process -Id $p.parent_pid -ErrorAction SilentlyContinue) {
    if ([DateTime]::UtcNow -gt $deadline) { exit 1 }
    Start-Sleep -Milliseconds 200
}
$success = $false
try {
    & $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -Plan $Plan -ApplyOnly
    $code = $LASTEXITCODE
    if ($code -eq 77) {
        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Plan "{1}" -ApplyOnly' -f $script,$Plan
        $process = Start-Process -FilePath $shell -ArgumentList $arguments -Verb RunAs -PassThru -Wait
        $code = $process.ExitCode
    }
    if ($code -ne 0) { throw 'Update installation failed or administrator authorization was cancelled' }
    $success = $true
} catch { Write-Error $_ -ErrorAction Continue }
@{success=$success;version=$p.version} | ConvertTo-Json | Set-Content -LiteralPath $p.receipt -Encoding UTF8
Start-Process -FilePath (Join-Path $p.destination 'easy-connect-gui.exe') -WorkingDirectory $p.destination
if ($success -and (Test-Path -LiteralPath $p.backup)) { Remove-Item -LiteralPath $p.backup -Recurse -Force -ErrorAction SilentlyContinue }
if ($success) { Remove-Item -LiteralPath (Split-Path -Parent $Plan) -Recurse -Force -ErrorAction SilentlyContinue }
