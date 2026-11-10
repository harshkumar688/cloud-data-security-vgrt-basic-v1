# V-GRT Secure Cloud - Local PowerShell Launcher
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $PSScriptRoot

if (-not $env:PORT) {
    $env:PORT = "8081"
}

# Auto-detect local JDK if not in PATH
if (-not $env:JAVA_HOME) {
    if (Test-Path "C:\Users\harsh\Downloads\jdk-23.0.2") {
        $env:JAVA_HOME = "C:\Users\harsh\Downloads\jdk-23.0.2"
    }
}
if ($env:JAVA_HOME) {
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
}

Write-Host "Building V-GRT project..." -ForegroundColor Cyan
& .\mvnw.cmd -DskipTests package
if ($LASTEXITCODE -ne 0) {
    Write-Error "Maven build failed."
    exit $LASTEXITCODE
}

Write-Host "Generating ephemeral RSA keys for this session..." -ForegroundColor Cyan
$keyLines = & java -jar target\secure-cloud-0.1.0.jar --generate-crypto-keys
foreach ($line in $keyLines) {
    if ($line -match "^VGRT_RSA_PUBLIC_KEY=(.*)$") {
        $env:VGRT_RSA_PUBLIC_KEY = $matches[1]
    }
    if ($line -match "^VGRT_RSA_PRIVATE_KEY=(.*)$") {
        $env:VGRT_RSA_PRIVATE_KEY = $matches[1]
    }
}

if (-not $env:VGRT_RSA_PUBLIC_KEY -or -not $env:VGRT_RSA_PRIVATE_KEY) {
    Write-Error "Failed to generate RSA keys."
    exit 1
}

Write-Host "`n=======================================================" -ForegroundColor Green
Write-Host "  V-GRT Secure Cloud is starting!" -ForegroundColor Green
Write-Host "  URL: http://localhost:$env:PORT" -ForegroundColor Green
Write-Host "=======================================================`n" -ForegroundColor Green

& .\mvnw.cmd spring-boot:run
