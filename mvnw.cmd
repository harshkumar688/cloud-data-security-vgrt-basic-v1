@echo off
setlocal
set "MAVEN_VERSION=3.9.11"
set "CACHE_DIR=%USERPROFILE%\.m2\wrapper\dists\apache-maven-%MAVEN_VERSION%"
set "MAVEN_HOME=%CACHE_DIR%\apache-maven-%MAVEN_VERSION%"
if exist "%MAVEN_HOME%\bin\mvn.cmd" goto run_maven
if not exist "%CACHE_DIR%" mkdir "%CACHE_DIR%"
set "ARCHIVE=%CACHE_DIR%\apache-maven-%MAVEN_VERSION%-bin.zip"
echo Downloading Apache Maven %MAVEN_VERSION% for this project...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri 'https://archive.apache.org/dist/maven/maven-3/%MAVEN_VERSION%/binaries/apache-maven-%MAVEN_VERSION%-bin.zip' -OutFile '%ARCHIVE%'"
if errorlevel 1 exit /b 1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%ARCHIVE%' -DestinationPath '%CACHE_DIR%' -Force"
if errorlevel 1 exit /b 1
:run_maven
call "%MAVEN_HOME%\bin\mvn.cmd" %*
exit /b %ERRORLEVEL%
