#requires -Version 5.1
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$ChecksumPath = Join-Path $Root 'CHECKSUMS.sha256'
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$Files = Get-ChildItem -Path $Root -Recurse -File |
    Where-Object {
        $_.FullName -notmatch '[\\/]\.git[\\/]' -and
        $_.FullName -notmatch '[\\/]CHECKSUMS\.sha256$'
    } |
    Sort-Object FullName

$Lines = foreach ($File in $Files) {
    $Hash = Get-FileHash -Path $File.FullName -Algorithm SHA256
    $RelativePath = $File.FullName.Substring($Root.Length + 1).Replace('\', '/')
    "$($Hash.Hash.ToLowerInvariant())  $RelativePath"
}

[System.IO.File]::WriteAllText($ChecksumPath, ($Lines -join "`n") + "`n", $Utf8NoBom)
Write-Host "CHECKSUMS.sha256 refreshed."
