@echo off
setlocal
cd /d "%~dp0"
if not defined PORT set "PORT=8080"

call mvnw.cmd -DskipTests package
if errorlevel 1 exit /b %errorlevel%

for /f "tokens=1,* delims==" %%A in ('java -jar target\secure-cloud-0.1.0.jar --generate-crypto-keys') do (
    if "%%A"=="VGRT_RSA_PUBLIC_KEY" set "VGRT_RSA_PUBLIC_KEY=%%B"
    if "%%A"=="VGRT_RSA_PRIVATE_KEY" set "VGRT_RSA_PRIVATE_KEY=%%B"
)

if not defined VGRT_RSA_PUBLIC_KEY (
    echo Failed to generate RSA keys.
    exit /b 1
)
if not defined VGRT_RSA_PRIVATE_KEY (
    echo Failed to generate RSA keys.
    exit /b 1
)

echo Starting local demo at http://localhost:%PORT%
call mvnw.cmd spring-boot:run