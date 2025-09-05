# Hybrid Malware Detector: Quick Start

## Overview
This system combines EMBER+LightGBM and a MalConv-style 1D CNN for robust malware detection on Windows PE files. It exposes a FastAPI HTTP server for binary classification.

## Usage

### 1. Training
- **EMBER+LightGBM**: Place your EMBER features/labels as `ember_features.npy` and `ember_labels.npy`. Run:
	```
	python train_ember.py
	```
	This saves `ember_lgbm.model`.
- **MalConv**: Train your model separately and save as `malconv.pt` (see `malconv.py` for architecture).

### 2. Inference Server
- Start the server:
	```
	uvicorn server:app --host 0.0.0.0 --port 8080 --workers 1
	```
- Or use Docker:
	```
	docker build -t hybrid-malware-detector .
	docker run -p 8080:8080 hybrid-malware-detector
	```

### 3. API
- POST a PE file as binary to `http://<host>:8080/` with `Content-Type: application/octet-stream`.
- Response: `{ "result": 0 }` (goodware) or `{ "result": 1 }` (malware)

## Requirements
- Python 3.10+
- See `requirements.txt`

## Notes
- Max file size: 2 MiB
- RAM: <1GB, response: <5s/sample
- You must provide trained model files: `ember_lgbm.model` and `malconv.pt`

## License
For academic/educational use only.