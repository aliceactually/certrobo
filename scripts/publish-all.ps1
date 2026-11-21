#!/usr/bin/env pwsh
# Adapted from CloudTransformer's multi-platform publish script. CertRobo's web
# assets and configuration must travel alongside the self-contained executable.
[CmdletBinding()]
param(
    [string[]] $RuntimeIdentifiers = @(
        'win-x64', 'win-arm64', 'osx-x64', 'osx-arm64', 'linux-x64', 'linux-arm64'
    ),
    [string] $OutputDirectory = (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) '..') 'certrobo-release'),
    [ValidateSet('Optimal', 'Fastest', 'NoCompression')]
    [string] $CompressionLevel = 'Optimal'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$projectDirectory = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$output = [IO.Path]::GetFullPath($OutputDirectory)
$comparison = if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    [StringComparison]::OrdinalIgnoreCase
} else {
    [StringComparison]::Ordinal
}
$prefix = $projectDirectory.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($output.Equals($projectDirectory, $comparison) -or $output.StartsWith($prefix, $comparison)) {
    throw 'OutputDirectory must be outside the project tree to avoid republishing old output.'
}

$allowed = @('win-x64', 'win-arm64', 'osx-x64', 'osx-arm64', 'linux-x64', 'linux-arm64')
if ($RuntimeIdentifiers.Count -eq 0 -or @($RuntimeIdentifiers | Where-Object { $_ -notin $allowed }).Count -gt 0) {
    throw 'Specify at least one supported runtime identifier.'
}
if (($RuntimeIdentifiers | Select-Object -Unique).Count -ne $RuntimeIdentifiers.Count) {
    throw 'Runtime identifiers must not be repeated.'
}

New-Item -ItemType Directory -Path $output -Force | Out-Null
foreach ($rid in $RuntimeIdentifiers) {
    $archive = Join-Path $output "CertRobo-$rid.zip"
    if (Test-Path -LiteralPath $archive) { throw "Archive already exists: $archive" }
}

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("certrobo-publish-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    foreach ($rid in $RuntimeIdentifiers) {
        $publish = Join-Path $tempRoot $rid
        Write-Host "Publishing $rid..."
        & dotnet publish (Join-Path $projectDirectory 'CertRobo.csproj') -c Release -r $rid --self-contained true -p:DebugType=none -o $publish
        if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $rid (exit $LASTEXITCODE)." }

        $executable = if ($rid.StartsWith('win-')) { 'CertRobo.exe' } else { 'CertRobo' }
        foreach ($path in @($executable, 'appsettings.json', 'wwwroot', 'static', 'Resources/Passphrases/eff_large_wordlist.txt')) {
            if (-not (Test-Path -LiteralPath (Join-Path $publish $path))) { throw "Missing $path in $rid output." }
        }
        $stagedArchive = Join-Path $tempRoot "CertRobo-$rid.zip"
        Write-Host "Compressing $rid ($CompressionLevel)..."
        $compressionTimer = [Diagnostics.Stopwatch]::StartNew()
        # Stream the directory through .NET rather than Compress-Archive's
        # PowerShell byte-copy loop. Keep the existing compression level and
        # put the publish contents directly at the archive root.
        [IO.Compression.ZipFile]::CreateFromDirectory(
            $publish, $stagedArchive, [IO.Compression.CompressionLevel] $CompressionLevel, $false
        )
        $compressionTimer.Stop()
        Write-Host ("Compressed {0} in {1:N1}s ({2:N1} MiB)." -f $rid,
            $compressionTimer.Elapsed.TotalSeconds, (([IO.FileInfo]$stagedArchive).Length / 1MB))
        Move-Item -LiteralPath $stagedArchive -Destination (Join-Path $output "CertRobo-$rid.zip")
    }
} finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}
Write-Host "Release archives are in $output"
