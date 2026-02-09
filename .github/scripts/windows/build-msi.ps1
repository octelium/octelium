param(
    [Parameter(Mandatory=$true)]
    [string]$PackageName,
    
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [Parameter(Mandatory=$true)]
    [string]$Arch,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeWireGuard
)

$ErrorActionPreference = "Stop"

$WixPlatform = if ($Arch -eq "amd64") { "x64" } else { "ARM64" }

$ComponentGuids = @{
    'octelium' = @{
        'MainExe' = 'AF4CA0D6-6605-4951-B837-8BB7EA8D91E1'
        'WireGuardDll' = '8352CC11-3CE1-4BA4-A80B-81E9606038DB'
        'Path' = 'B9F2DB53-9911-468D-8864-E58A87B0695F'
    }
    'octeliumctl' = @{
        'MainExe' = '84FEEA5E-F013-4D69-97F6-FE3E775EC74B'
        'Path' = 'C543B799-73AA-4D06-89A0-1A50E1CBF4CB'
    }
    'octops' = @{
        'MainExe' = '624F2002-586D-4E1F-A857-366903725BEC'
        'Path' = '54110960-589B-49CF-B58D-4CA49976847D'
    }
}

$UpgradeCode = switch ($PackageName) {
    "octelium"    { "486B31DE-6F3A-4BD3-AE25-C13FA2A04DE1" }
    "octeliumctl" { "1F5ABCD8-90BD-4045-8D66-44F393D527CB" }
    "octops"      { "63231D5F-9EDA-43E2-931E-693A08ACFF3E" }
    default       { throw "Unknown package name: $PackageName" }
}

$ComponentGuid1 = $ComponentGuids[$PackageName]['MainExe']
$ComponentGuid2 = if ($IncludeWireGuard) { $ComponentGuids[$PackageName]['WireGuardDll'] } else { $null }
$PathGuid = $ComponentGuids[$PackageName]['Path']

$Description = switch ($PackageName) {
    "octelium"    { "Octelium - Zero trust secure access platform with VPN, ZTNA, and API/AI/MCP gateway capabilities" }
    "octeliumctl" { "Octeliumctl - Control and management CLI for Octelium" }
    "octops"      { "Octops - Operations and administration tool for Octelium" }
    default       { "$PackageName - Octelium suite component" }
}

New-Item -ItemType Directory -Force -Path "packaging/msi" | Out-Null
New-Item -ItemType Directory -Force -Path "packaging" | Out-Null

$templatePath = if ($IncludeWireGuard) {
    ".github/scripts/windows/template-with-dll.wxs"
} else {
    ".github/scripts/windows/template.wxs"
}

Write-Host "Using template: $templatePath"

if (-not (Test-Path $templatePath)) {
    throw "Template file not found: $templatePath"
}

$wxsContent = Get-Content $templatePath -Raw
$wxsContent = $wxsContent -replace '\$\{PACKAGE_NAME\}', $PackageName
$wxsContent = $wxsContent -replace '\$\{VERSION\}', $Version
$wxsContent = $wxsContent -replace '\$\{UPGRADE_CODE\}', $UpgradeCode
$wxsContent = $wxsContent -replace '\$\{DESCRIPTION\}', $Description
$wxsContent = $wxsContent -replace '\$\{COMPONENT_GUID_1\}', $ComponentGuid1
$wxsContent = $wxsContent -replace '\$\{COMPONENT_GUID_2\}', $ComponentGuid2
$wxsContent = $wxsContent -replace '\$\{PATH_GUID\}', $PathGuid

$wxsPath = "packaging/msi/$PackageName.wxs"
$wxsContent | Out-File -FilePath $wxsPath -Encoding UTF8

Write-Host "Generated WXS file: $wxsPath"

Write-Host "Building MSI for $PackageName ($WixPlatform)..."
$msiPath = "packaging/$PackageName-$Version-$Arch.msi"

wix build -arch $WixPlatform -o $msiPath $wxsPath

if ($LASTEXITCODE -ne 0) {
    throw "WiX build failed with exit code $LASTEXITCODE"
}

Write-Host "Successfully created: $msiPath"