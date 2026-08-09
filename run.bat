@echo off
title ParkSmart
cd /d "%~dp0"
if not exist .venv (
  py -m venv .venv
)
call .venv\Scripts\activate
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload
pause
