@echo off
title Zero-Trust Auth - Python FastAPI Server
cd /d "%~dp0python-fastapi"
echo Starting Zero-Trust Python FastAPI Server on http://127.0.0.1:8001 ...
echo API Swagger Docs available at http://127.0.0.1:8001/docs
".venv\Scripts\python.exe" zero_trust_auth.py
pause
