@echo off
echo ========================================
echo  Phishing URL Detector Web Application
echo ========================================
echo.
echo Starting the web application...
echo The app will open in your default browser
echo If it doesn't open automatically, visit: http://localhost:8501
echo.
echo Press Ctrl+C to stop the server
echo.
echo ========================================
echo.

python -m streamlit run phishing_gui.py

echo.
echo Application stopped.
pause