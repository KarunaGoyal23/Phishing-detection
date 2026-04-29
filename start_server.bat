@echo off
echo ========================================
echo    Advanced Phishing Detection Server
echo ========================================
echo.

REM 
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

REM 
if not exist "phishing_dataset.csv" (
    echo ERROR: phishing_dataset.csv not found
    echo Please ensure the dataset file is in the current directory
    pause
    exit /b 1
)

REM 
if not exist "advanced_phishing_model.pkl" (
    echo Advanced model not found. Training new model...
    echo This may take several minutes...
    python train_advanced_model.py
    if errorlevel 1 (
        echo ERROR: Model training failed
        pause
        exit /b 1
    )
    echo Model training completed successfully!
    echo.
)

REM 
echo Checking dependencies...
pip install -r requirements.txt >nul 2>&1

echo.
echo Starting Phishing Detection Server...
echo Server will be available at: http://localhost:5000
echo Press Ctrl+C to stop the server
echo.

REM
python phishing_server.py --host 0.0.0.0 --port 5000

pause 