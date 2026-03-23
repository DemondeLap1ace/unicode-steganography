@echo off
cd /d "%~dp0\pua-npm"

echo ======================================================
echo   Unicode PUA Invisible Payload - npm PoC
echo ======================================================
echo.

echo [1/4] Building invisible payload...
python build.py
if errorlevel 1 (echo BUILD FAILED & exit /b 1)
echo.

echo [2/4] Installing package (triggers postinstall)...
cd consumer
call npm install --foreground-scripts
if errorlevel 1 (echo INSTALL FAILED & exit /b 1)
echo.

echo [3/4] Running detection scan...
cd ..
python detect.py invisible-utils/ --hex-context 8
echo.

echo [4/4] Testing legitimate functionality...
cd consumer
node app.js
echo.

echo ======================================================
echo   Complete. Check your Desktop for the HTML file.
echo ======================================================
