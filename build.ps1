<#
  Builds MG SiteLimiter into .\dist\MGSL Installer.exe
  Needs the .NET 10 SDK: https://dotnet.microsoft.com/download/dotnet/10.0

    .\build.ps1                     # x64 Windows
    .\build.ps1 -Runtime win-arm64  # ARM64 Windows

  The installer is one self-contained file (no .NET runtime needed on the target PC).
  It installs a copy of itself as the service and adds "MGSL Uninstaller.exe" next to it.
#>
param([string]$Runtime = 'win-x64')
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

Write-Host '== Core tests' -ForegroundColor Cyan
dotnet run --project tests/SiteLimiter.Core.Tests -c Release
if ($LASTEXITCODE -ne 0) { throw 'Core tests failed' }

Write-Host "== Publishing ($Runtime)" -ForegroundColor Cyan
$out = Join-Path $PSScriptRoot 'obj\publish'
if (Test-Path $out) { Remove-Item $out -Recurse -Force }
dotnet publish src/SiteLimiter/SiteLimiter.csproj -c Release -r $Runtime -o $out `
    --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=false `
    -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=none
if ($LASTEXITCODE -ne 0) { throw 'Publish failed' }

if (Test-Path dist) { Remove-Item dist -Recurse -Force }
New-Item -ItemType Directory dist | Out-Null
Copy-Item (Join-Path $out 'SiteLimiter.exe') 'dist\MGSL Installer.exe'

Write-Host "`nBuilt: $PSScriptRoot\dist\MGSL Installer.exe" -ForegroundColor Green
Write-Host 'Double-click it to install (it asks for administrator rights).'
