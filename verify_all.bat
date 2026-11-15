@echo off
title Zero-Trust Verification Suite
cd /d "%~dp0"
echo Running Zero-Trust Verification Suite...
".\python-fastapi\.venv\Scripts\python.exe" test_zero_trust.py
pause
