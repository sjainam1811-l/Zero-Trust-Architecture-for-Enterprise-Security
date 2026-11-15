@echo off
title Zero-Trust Console Launcher
setlocal EnableDelayedExpansion

:: 1. Set environment paths so Node, npm, and Python always work
set "PATH=%LOCALAPPDATA%\Programs\nodejs;%APPDATA%\npm;C:\Program Files\nodejs;C:\Program Files\Python313;%PATH%"

cd /d "%~dp0"

echo ======================================================================
echo    ZERO-TRUST CONSOLE: Enterprise Security Lab Launcher
echo    Minor Project 2: Zero Trust Architecture for Enterprise Security
echo ======================================================================
echo.
echo [*] Starting Services...
echo.

:: 2. Launch Node.js Express Gateway (Port 4000)
echo [1/3] Starting Node.js Auth Gateway (Port 4000)...
start "1. Node.js Auth Gateway [Port 4000]" cmd /k "title Node.js Auth Gateway (Port 4000) && cd /d "%~dp0node-express" && set "PATH=%LOCALAPPDATA%\Programs\nodejs;%APPDATA%\npm;C:\Program Files\nodejs;%PATH%" && node server.js"

:: 3. Launch Python FastAPI Workload (Port 8001)
echo [2/3] Starting Python FastAPI Workload Service (Port 8001)...
start "2. Python FastAPI Workload [Port 8001]" cmd /k "title Python FastAPI Workload (Port 8001) && cd /d "%~dp0python-fastapi" && .venv\Scripts\python.exe zero_trust_auth.py"

:: 4. Launch React Vite Frontend (Port 5173)
echo [3/3] Starting React Vite Frontend Console (Port 5173)...
start "3. React Frontend Console [Port 5173]" cmd /k "title React Frontend Console (Port 5173) && cd /d "%~dp0react-frontend" && set "PATH=%LOCALAPPDATA%\Programs\nodejs;%APPDATA%\npm;C:\Program Files\nodejs;%PATH%" && npx vite --port 5173 --host 127.0.0.1"

:: Wait 3 seconds for services to initialize
timeout /t 3 /nobreak >nul

:: 5. Open Web Browser to Console
echo.
echo [*] Launching Web Browser at http://localhost:5173 ...
start http://localhost:5173

echo.
echo ======================================================================
echo  [SUCCESS] All Zero-Trust services are running!
echo ======================================================================
echo   - Web Console:       http://localhost:5173
echo   - Auth Gateway API:  http://localhost:4000
echo   - Workload API:      http://127.0.0.1:8001 (Docs: http://127.0.0.1:8001/docs)
echo.
echo  Default Accounts:
echo   - Admin:  admin@enterprise.internal / admin123
echo   - Editor: user@example.com          / password123
echo.
echo  Press any key to close this launcher window (services keep running).
echo ======================================================================
pause >nul
