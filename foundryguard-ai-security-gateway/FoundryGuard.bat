@echo off
cd /d D:\AI-Security-Labs\foundryguard-ai-security-gateway
start "FoundryGuard Server" cmd /k python run.py
timeout /t 8 >nul
start "" http://localhost:8565