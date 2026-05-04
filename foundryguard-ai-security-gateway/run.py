import subprocess
import sys

def run_api():
    return subprocess.Popen([
        sys.executable, "-m", "uvicorn", "app.main:app", "--reload"
    ])

def run_ui():
    return subprocess.Popen([
        sys.executable, "-m", "streamlit", "run", "dashboard.py"
    ])

if __name__ == "__main__":
    print("Starting FoundryGuard...")

    api_process = run_api()
    ui_process = run_ui()

    try:
        api_process.wait()
        ui_process.wait()
    except KeyboardInterrupt:
        print("Shutting down...")
        api_process.terminate()
        ui_process.terminate()
