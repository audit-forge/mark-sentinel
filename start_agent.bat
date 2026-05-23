@echo off
cd /d "C:\Sentinel"
C:\Python314\python.exe C:\Sentinel\agent.py --daemon --server http://localhost:7331 --profile default >> "C:\Sentinel\logs\agent.log" 2>&1
