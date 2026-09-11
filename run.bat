@echo off
title TrustID FastAPI Backend Server (SIH 2026)
echo ===================================================
echo   TrustID Multi-Evidence Document Screening Engine
echo   Team Conqueror - SIH 2026 (PS ID: SIH26188)
echo ===================================================
echo.
echo Starting FastAPI Uvicorn server on http://127.0.0.1:8000 ...
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
pause
