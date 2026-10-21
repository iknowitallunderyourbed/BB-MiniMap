@echo off
rem Builds dist\BBMapViewer.exe from bb_map_viewer.py (needs Python 3.8+ from python.org, with tkinter).
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller pillow
if errorlevel 1 goto :fail
python -m PyInstaller --noconfirm --clean --onefile --windowed --name BBMapViewer bb_map_viewer.py
if errorlevel 1 goto :fail
echo.
echo Done: %~dp0dist\BBMapViewer.exe
pause
exit /b 0
:fail
echo Build failed.
pause
exit /b 1
