import subprocess
import sys
import os
import importlib.util

def check_python_version():
    """Check if Python version is compatible."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python {version.major}.{version.minor} detected. Python 3.8+ required.")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK")
    return True

def check_required_files():
    """Check if required files exist."""
    required_files = [
        'phishing_gui.py',
        'phishing_analyzer.py', 
        'fusion_inference.py',
        'phishing_dataset.csv',
        'requirements.txt'
    ]
    
    missing_files = []
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file} - Found")
        else:
            print(f"❌ {file} - Missing")
            missing_files.append(file)
    
    return len(missing_files) == 0, missing_files

def check_dependencies():
    """Check if required packages are installed."""
    required_packages = [
        'streamlit',
        'pandas',
        'numpy',
        'xgboost',
        'joblib',
        'scikit-learn',
        'requests',
        'tldextract'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            importlib.import_module(package.replace('-', '_'))
            print(f"✅ {package} - Installed")
        except ImportError:
            print(f"❌ {package} - Not installed")
            missing_packages.append(package)
    
    return len(missing_packages) == 0, missing_packages

def install_dependencies():
    """Install missing dependencies."""
    print("\n🔧 Installing dependencies from requirements.txt...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                      check=True, capture_output=True, text=True)
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        print(f"Error output: {e.stderr}")
        return False

def run_streamlit():
    """Launch the Streamlit application."""
    print("\n🚀 Starting Phishing URL Detector Web Application...")
    print("📱 The app will open in your default browser")
    print("🔗 URL: http://localhost:8501")
    print("⏹️  Press Ctrl+C to stop the server")
    print("-" * 60)
    
    try:
        subprocess.run([sys.executable, '-m', 'streamlit', 'run', 'phishing_gui.py'])
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")

def main():
    """Main setup and deployment function."""
    print("🔍 Phishing URL Detector - Deployment Checker")
    print("=" * 50)

    if not check_python_version():
        return 1

    files_ok, missing_files = check_required_files()
    if not files_ok:
        print(f"\n❌ Missing required files: {', '.join(missing_files)}")
        print("Please ensure all project files are present.")
        return 1

    deps_ok, missing_deps = check_dependencies()
    if not deps_ok:
        print(f"\n⚠️  Missing packages: {', '.join(missing_deps)}")

        response = input("\nWould you like to install missing dependencies? (y/n): ")
        if response.lower() in ['y', 'yes']:
            if not install_dependencies():
                return 1
        else:
            print("Please install the missing dependencies manually:")
            print("pip install -r requirements.txt")
            return 1
    
    print("\n✅ All checks passed!")
    print("\n" + "=" * 50)

    response = input("Start the web application now? (y/n): ")
    if response.lower() in ['y', 'yes']:
        run_streamlit()
    else:
        print("\nTo start the application later, run:")
        print("streamlit run phishing_gui.py")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())