param([string]$ExpectedTag = '')
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$gradleText = [IO.File]::ReadAllText((Join-Path $repoRoot 'build.gradle'))
$versionMatch = [regex]::Match($gradleText, "(?m)^version = '([0-9]+\.[0-9]+(?:\.[0-9]+)?)'")
if (-not $versionMatch.Success) { throw 'Cannot read release version from build.gradle' }
$releaseVersion = $versionMatch.Groups[1].Value
if ($ExpectedTag -and $ExpectedTag -cne "v$releaseVersion") { throw "Tag $ExpectedTag does not match version $releaseVersion" }
$versionFiles = @{
    'src/main/java/modchecker/Main.java' = "ModChecker $releaseVersion"
    'src/main/java/modchecker/gui/ModCheckerFrame.java' = "ModChecker $releaseVersion"
    'src/main/java/modchecker/online/OnlineChecker.java' = "modchecker/$releaseVersion"
    'README.md' = "# ModChecker $releaseVersion"
    'README.txt' = "ModChecker $releaseVersion"
}
foreach ($versionFile in $versionFiles.Keys) {
    if (-not [IO.File]::ReadAllText((Join-Path $repoRoot $versionFile)).Contains($versionFiles[$versionFile])) {
        throw "Version mismatch in $versionFile"
    }
}
$releaseJar = Join-Path $repoRoot 'build/libs/modchecker.jar'
if (-not (Test-Path -LiteralPath $releaseJar -PathType Leaf)) { throw 'Run gradlew build selfTest first' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($releaseJar)
try {
    $entry = $archive.GetEntry('META-INF/MANIFEST.MF')
    if ($null -eq $entry) { throw 'Manifest is missing' }
    $reader = [IO.StreamReader]::new($entry.Open())
    try { $manifestText = $reader.ReadToEnd() } finally { $reader.Dispose() }
    if ($manifestText -notmatch "(?m)^Implementation-Version: $([regex]::Escape($releaseVersion))\r?$") { throw 'JAR manifest version mismatch' }
} finally { $archive.Dispose() }
$releaseDir = Join-Path $repoRoot "build/release/$releaseVersion"
New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
Copy-Item -LiteralPath $releaseJar -Destination (Join-Path $releaseDir 'modchecker.jar') -Force
Copy-Item -LiteralPath (Join-Path $repoRoot 'README.txt') -Destination (Join-Path $releaseDir 'README.txt') -Force
$zipName = "modchecker-v$releaseVersion.zip"
$zipPath = Join-Path $releaseDir $zipName
$stream = [IO.File]::Open($zipPath, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite)
try {
    $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($name in @('modchecker.jar', 'README.txt')) {
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $releaseDir $name), $name) | Out-Null
        }
    } finally { $zip.Dispose() }
} finally { $stream.Dispose() }
$checksumLines = foreach ($name in @('modchecker.jar', 'README.txt', $zipName)) {
    $digest = (Get-FileHash -LiteralPath (Join-Path $releaseDir $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$digest  $name"
}
[IO.File]::WriteAllText((Join-Path $releaseDir 'SHA256SUMS.txt'), (($checksumLines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "Packaged ModChecker $releaseVersion in $releaseDir"
