param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('amd64', 'arm64')]
    [string]$Arch,

    [switch]$PrepareOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not $IsWindows -or $env:GITHUB_ACTIONS -ne 'true') {
    throw 'The MSI upgrade test requires an isolated GitHub Actions Windows runner'
}

$installPath = Join-Path $env:ProgramFiles 'Octelium/octelium'
if (Test-Path $installPath) {
    throw "Refusing to replace an existing installation at $installPath"
}

$temporaryPath = Join-Path $env:RUNNER_TEMP 'octelium-msi-upgrade'
New-Item -ItemType Directory -Force -Path $temporaryPath | Out-Null
if ($PrepareOnly) {
    New-Item -ItemType Directory -Force -Path bin | Out-Null
    Copy-Item native-tests/octelium.exe,native-tests/wireguard.dll,native-tests/wintun.dll -Destination bin

    & "$PSScriptRoot/prepare-drivers.ps1" -Arch $Arch -VerifyOnly
    & "$PSScriptRoot/build-msi.ps1" -PackageName octelium -Version '0.0.2' -Arch $Arch -IncludeWireGuard

    $archivePath = Join-Path $temporaryPath 'previous-wireguard.zip'
    Invoke-WebRequest -Uri 'https://download.wireguard.com/wireguard-nt/wireguard-nt-0.10.1.zip' -OutFile $archivePath -MaximumRetryCount 3 -TimeoutSec 60
    if ((Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLowerInvariant() -ne '772c0b1463d8d2212716f43f06f4594d880dea4f735165bd68e388fc41b81605') {
        throw 'Previous WireGuardNT archive SHA-256 mismatch'
    }
    $archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $member = $archive.GetEntry("wireguard-nt/bin/$Arch/wireguard.dll")
        if ($null -eq $member) {
            throw 'Previous WireGuardNT DLL is missing'
        }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($member, (Join-Path $PWD 'bin/wireguard.dll'), $true)
    } finally {
        $archive.Dispose()
    }
    (Get-FileHash -Algorithm SHA256 bin/wireguard.dll).Hash | Set-Content native-tests/previous-wireguard.sha256
    & "$PSScriptRoot/build-msi.ps1" -PackageName octelium -Version '0.0.1' -Arch $Arch -IncludeWireGuard
    return
}

$newPackage = (Resolve-Path "packaging/octelium-0.0.2-$Arch.msi").Path
$oldPackage = (Resolve-Path "packaging/octelium-0.0.1-$Arch.msi").Path
$previousHash = (Get-Content native-tests/previous-wireguard.sha256 -Raw).Trim()
$installedPackage = $null

try {
    foreach ($package in @($oldPackage, $newPackage)) {
        $logPath = Join-Path $temporaryPath "$([System.IO.Path]::GetFileName($package)).log"
        $process = Start-Process msiexec.exe -ArgumentList @('/i', "`"$package`"", '/qn', '/norestart', '/L*v', "`"$logPath`"") -Wait -PassThru
        if ($process.ExitCode -notin @(0, 3010)) {
            throw "MSI installation failed: $($process.ExitCode); see $logPath"
        }
        $installedPackage = $package
        if ($process.ExitCode -eq 3010) {
            throw 'The MSI test requires a reboot; the native upgrade has not been validated'
        }
        if ($package -eq $oldPackage) {
            $installedHash = (Get-FileHash -Algorithm SHA256 (Join-Path $installPath 'wireguard.dll')).Hash.ToLowerInvariant()
            if ($installedHash -ne $previousHash) {
                throw 'The previous driver payload was not installed'
            }
            Copy-Item native-tests/controller.test.exe -Destination $installPath
            $executable = Join-Path $installPath 'controller.test.exe'
            $legacyTest = 'TestWindowsNativeLegacyWireGuardDriver'
            $tests = & $executable "-test.list=^$legacyTest`$"
            if ($LASTEXITCODE -ne 0 -or $tests -notcontains $legacyTest) {
                throw 'The legacy driver migration test is missing'
            }
            $env:OCTELIUM_TEST_WINDOWS_DRIVERS = '1'
            $env:OCTELIUM_TEST_WINDOWS_LEGACY_DRIVER = '1'
            try {
                & $executable '-test.v' '-test.timeout=2m' "-test.run=^$legacyTest`$"
                if ($LASTEXITCODE -ne 0) {
                    throw "Legacy driver setup failed: $LASTEXITCODE"
                }
            } finally {
                $env:OCTELIUM_TEST_WINDOWS_LEGACY_DRIVER = '0'
                Remove-Item $executable -Force -ErrorAction SilentlyContinue
            }
        }
    }

    & "$PSScriptRoot/prepare-drivers.ps1" -Arch $Arch -Destination $installPath -VerifyOnly
    if ((Get-FileHash -Algorithm SHA256 (Join-Path $installPath 'octelium.exe')).Hash -ne (Get-FileHash -Algorithm SHA256 native-tests/octelium.exe).Hash) {
        throw 'The installed client does not match the new driver build'
    }
    Copy-Item native-tests/controller.test.exe -Destination $installPath
    $env:OCTELIUM_TEST_WINDOWS_DRIVERS = '1'
    & (Join-Path $installPath 'controller.test.exe') '-test.v' '-test.timeout=5m' '-test.run=^TestWindowsNative'
    if ($LASTEXITCODE -ne 0) {
        throw "Installed driver tests failed: $LASTEXITCODE"
    }
} finally {
    Remove-Item (Join-Path $installPath 'controller.test.exe') -Force -ErrorAction SilentlyContinue
    if ($null -ne $installedPackage) {
        $logPath = Join-Path $temporaryPath 'uninstall.log'
        $process = Start-Process msiexec.exe -ArgumentList @('/x', "`"$installedPackage`"", '/qn', '/norestart', '/L*v', "`"$logPath`"") -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "MSI uninstall failed: $($process.ExitCode); see $logPath"
        }
    }
}
