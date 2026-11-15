@echo off
title Zero-Trust Auth - Node.js Express Server
set "PATH=%LOCALAPPDATA%\Programs\nodejs;%APPDATA%\npm;C:\Program Files\nodejs;%PATH%"
cd /d "%~dp0node-express"
echo Starting Zero-Trust Node.js Express Server on http://localhost:4000 ...
node server.js
pause
