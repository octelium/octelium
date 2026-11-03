param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('amd64', 'arm64')]
    [string]$Arch,

    [string]$Destination = 'bin',

    [switch]$VerifyOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$manifest = Get-Content (Join-Path $PSScriptRoot 'drivers.json') -Raw | ConvertFrom-Json
$destinationPath = [System.IO.Path]::GetFullPath($Destination)
$temporaryPath = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
$machine = if ($Arch -eq 'amd64') { 0x8664 } else { 0xAA64 }

try {
    New-Item -ItemType Directory -Path $temporaryPath | Out-Null

    foreach ($entry in $manifest.PSObject.Properties) {
        $driver = $entry.Value
        $fileName = "$($entry.Name).dll"
        $filePath = Join-Path $destinationPath $fileName

        if (-not $VerifyOnly) {
            $archivePath = Join-Path $temporaryPath "$($entry.Name).zip"
            Invoke-WebRequest -Uri $driver.url -OutFile $archivePath -MaximumRetryCount 3 -TimeoutSec 60
            if ((Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLowerInvariant() -ne $driver.sha256) {
                throw "$($entry.Name) archive SHA-256 mismatch"
            }

            $archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
            try {
                $member = $archive.GetEntry("$($driver.root)/bin/$Arch/$fileName")
                if ($null -eq $member) {
                    throw "$fileName is missing for $Arch"
                }
                $filePath = Join-Path $temporaryPath $fileName
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($member, $filePath)
            } finally {
                $archive.Dispose()
            }
        }

        if ((Get-FileHash -Algorithm SHA256 $filePath).Hash.ToLowerInvariant() -ne $driver.dllSha256.$Arch) {
            throw "$fileName SHA-256 mismatch for $Arch"
        }

        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
            throw "$fileName has an invalid DOS header"
        }
        $offset = [System.BitConverter]::ToInt32($bytes, 0x3C)
        if ($offset -lt 0 -or $offset -gt $bytes.Length - 6 -or
            [System.BitConverter]::ToUInt32($bytes, $offset) -ne 0x4550 -or
            [System.BitConverter]::ToUInt16($bytes, $offset + 4) -ne $machine) {
            throw "$fileName has an invalid PE header or architecture for $Arch"
        }

        if ($IsWindows) {
            $signature = Get-AuthenticodeSignature -FilePath $filePath
            if ($signature.Status -ne 'Valid') {
                throw "$fileName has an invalid Authenticode signature: $($signature.Status)"
            }
        }
        Write-Host "Verified $($entry.Name) $($driver.version) for $Arch"
    }

    if (-not $VerifyOnly) {
        New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
        Copy-Item (Join-Path $temporaryPath '*.dll') -Destination $destinationPath
    }
} finally {
    Remove-Item -LiteralPath $temporaryPath -Recurse -Force -ErrorAction SilentlyContinue
}
