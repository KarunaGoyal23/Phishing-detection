# Phishing URL Detector 

A comprehensive web-based phishing detection system built with Streamlit and advanced machine learning models.

## 🌟 Features

- **Real-time URL Analysis**: Instant phishing detection with risk scoring (0-100)
- **Advanced AI Models**: Multiple ML models including XGBoost and fusion models
- **Comprehensive Analysis**: 
  - URL structure analysis
  - Domain reputation checking
  - Brand impersonation detection
  - SSL certificate validation
  - Typosquatting detection
- **Interactive Web Interface**: Built with Streamlit for easy use
- **Educational Content**: Learn about phishing protection
- **Risk Scoring**: Clear risk levels with detailed explanations

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone or download this repository**

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the web application:**
   ```bash
   streamlit run phishing_gui.py
   ```

4. **Open your browser** to the URL shown in the terminal (typically `http://localhost:8501`)

3. Install dependencies:

    ```powershell
    pip install -r requirements.txt
    ```

4. Ensure `phishing_dataset.csv` and, if available, `advanced_fusion_artifact.pkl` are in the project root.

## Quick start

Start the server (default host 0.0.0.0, port 5000):

```powershell
python phishing_server.py --host 0.0.0.0 --port 5000
```

Run the interactive client:

```powershell
python phishing_client.py --interactive
```

Analyze a single URL:

```powershell
python phishing_client.py --url "https://suspicious-site.example"
```

Open the Streamlit GUI:

```powershell
streamlit run phishing_gui.py
```

Train (if you need to build a new model):

```powershell
python train_advanced_model.py
```

## Project layout

- `advanced_phishing_model.py` — fusion model implementation
- `fusion_inference.py` — model inference helpers
- `phishing_server.py` — JSON API server
- `phishing_client.py` — CLI client for interactive and batch requests
- `phishing_analyzer.py` — lightweight URL analyzer
- `phishing_gui.py` — Streamlit UI
- `phishing_dataset.csv` — dataset for training/testing
- `advanced_fusion_artifact.pkl` — pre-trained model artifact (optional)
- `requirements.txt` — Python dependencies
- `test_advanced_system.py` — smoke tests/examples

## API (common JSON payloads)

Analyze single URL:

```json
{ "type": "analyze", "url": "https://example.com" }
```

Batch analyze:

```json
{ "type": "batch_analyze", "urls": ["url1", "url2"] }
```

Health check:

```json
{ "type": "health" }
```

Typical response structure (fields may vary):

```json
{
  "status": "success",
  "url": "https://example.com",
  "analysis": {
    "basic": { "risk_score": 75, "risk_level": "High" },
    "advanced": { "prediction": 1, "probability": 0.85 },
    "combined": { "risk_score": 78.5, "processing_time": 1.2 }
  },
  "timestamp": "2025-08-27T12:00:00"
}
```

See `phishing_client.py` for the exact communication protocol the client uses with the server.

## Testing

Run unit tests or smoke checks:

```powershell
python -m pytest -q
```

Or run the included smoke test:

```powershell
python test_advanced_system.py
```

## Troubleshooting

- If the server fails to start, ensure `advanced_fusion_artifact.pkl` exists or train the model.
- If dependencies are missing, reinstall inside the activated virtual environment: `pip install -r requirements.txt`.
- Check `phishing_server.log` for runtime errors.

## Contributing

- Fork, create a feature branch, add tests, and open a PR. Keep changes small and focused.

## License & Disclaimer

- MIT (see `LICENSE` if present).
- Disclaimer: ML-based predictions are heuristics and not a substitute for full security controls.

---

If you'd like, I can add a one-file example that calls the server and prints a human-readable report or create a minimal `README-quick.md` with only PowerShell one-liners.
