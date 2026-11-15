@echo off
title Zero-Trust Auth - React Frontend Dashboard
set "PATH=%LOCALAPPDATA%\Programs\nodejs;%APPDATA%\npm;C:\Program Files\nodejs;%PATH%"
cd /d "%~dp0react-frontend"
echo Starting Zero-Trust React Frontend on http://localhost:5173 ...
npx vite --port 5173 --host 127.0.0.1
pause
