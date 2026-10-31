@echo off
setlocal
cd /d "%~dp0"
if not defined PORT set "PORT=8080"
set "SERVER_ADDRESS=0.0.0.0"

echo Starting V-GRT for devices on this local network.
echo On this PC: http://localhost:%PORT%
echo On another device on the same Wi-Fi, open http://YOUR-PC-IP:%PORT%
echo Find YOUR-PC-IP by running ipconfig and checking the active network adapter's IPv4 address.
echo Allow Java through Windows Firewall on Private networks if prompted.
echo Do not expose this demo to the public internet.

call run-local.cmd