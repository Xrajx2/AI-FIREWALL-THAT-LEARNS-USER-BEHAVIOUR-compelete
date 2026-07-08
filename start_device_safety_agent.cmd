@echo off
cd /d "%~dp0"
start "AI Firewall Device Safety Agent" /min py -3 "%~dp0backend\device_safety_agent.py"
