import subprocess
import sys
import os

def main():
    """Run the Streamlit application."""
    if not os.path.exists('phishing_gui.py'):
        print("❌ Error: phishing_gui.py not found!")
        print("Please make sure you're running this script from the project directory.")
        return 1

    required_files = ['phishing_dataset.csv', 'phishing_analyzer.py', 'fusion_inference.py']
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        print(f"❌ Error: Missing required files: {', '.join(missing_files)}")
        return 1
    
    print("🚀 Starting Phishing URL Detector Web Application...")
    print("📱 The app will open in your default browser")
    print("🔗 If it doesn't open automatically, visit: http://localhost:8501")
    print("⏹️  Press Ctrl+C to stop the server")
    print("-" * 60)
    
    try:
        subprocess.run([sys.executable, '-m', 'streamlit', 'run', 'phishing_gui.py'], check=True)
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error running Streamlit: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())