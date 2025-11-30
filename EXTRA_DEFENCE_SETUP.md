# Extra Defence Branch Setup Summary

## Overview
This document summarizes the changes made to create the `extra_defence` branch based on `SubmissionFinal`, integrating Model1 RandomForest Deep as the defense model.

## Branch Information
- **Base Branch**: `SubmissionFinal` (origin/SubmissionFinal)
- **New Branch**: `extra_defence`
- **Purpose**: Submit Model1 RandomForest Deep as extra defense method

## Files Created/Modified

### New Files Created:
1. **`defender/defender/models/model1_rf_deep.py`**
   - New model class `Model1_RandomForest_Deep`
   - Loads `model1_best.pickle` file
   - Uses EMBER feature extractor (v2)
   - Implements `predict()` and `predict_proba()` methods
   - Compatible with existing defender infrastructure

2. **`defender/MODEL1_DOWNLOAD.md`**
   - Instructions for downloading the model file
   - Model details and verification steps
   - Placeholder for download URL

3. **`report.tex`**
   - Complete LaTeX report for submission
   - Documents 5 attack methods and 1 defense method
   - Includes performance metrics and technical details

### Modified Files:
1. **`defender/defender/__main__.py`**
   - Added import for `Model1_RandomForest_Deep`
   - Added loading logic for Model1 (default model)
   - Supports environment variables for configuration

2. **`defender/defender/models/__init__.py`**
   - Added export for `Model1_RandomForest_Deep`

3. **`defender/README.md`**
   - Added section "Using Model1 RandomForest Deep"
   - Includes download instructions and usage examples
   - Model performance metrics

## Model File Requirements

### Required File:
- **`defender/defender/models/model1_best.pickle`**
  - Not included in repository (too large)
  - Must be downloaded separately
  - See `defender/MODEL1_DOWNLOAD.md` for details

### Model Structure:
The pickle file should contain:
```python
{
    'classifier': RandomForestClassifier object,
    'scaler': MinMaxScaler object (optional),
    'feature_names': list (optional)
}
```

## Usage

### 1. Download Model File
```bash
# Download model1_best.pickle from provided URL
# Place it in: defender/defender/models/model1_best.pickle
```

### 2. Run Defender
```bash
cd defender
export DF_MODEL_NAME=model1
python -m defender
```

Or use default (Model1 is now the default):
```bash
cd defender
python -m defender
```

### 3. Customize Path (Optional)
```bash
export DF_MODEL1_PATH=/custom/path/to/model1_best.pickle
export DF_MODEL_THRESH=0.5
python -m defender
```

## Model Performance

Model1 RandomForest Deep performance metrics:
- **Accuracy**: 93.20%
- **Precision**: 98.16%
- **Recall**: 89.20%
- **F1-Score**: 93.47%
- **AUC-ROC**: 99.06%
- **False Positive Rate**: 2.01%

## Testing

Test the model loading:
```bash
cd defender
python -m defender.models.model1_rf_deep defender/models/model1_best.pickle
```

This should print model information if loaded correctly.

## Model Download

The model file can be downloaded from:
- **Google Drive Link**: https://drive.google.com/file/d/1GEsn_imO1m1c4on5UiJmP0S7Ku8PkqJu/view?usp=sharing

**Quick download:**
```bash
pip install gdown
gdown https://drive.google.com/uc?id=1GEsn_imO1m1c4on5UiJmP0S7Ku8PkqJu -O defender/defender/models/model1_best.pickle
```

## Next Steps

1. **Download Model File**: Download `model1_best.pickle` from the Google Drive link above
2. **Test Deployment**: Verify the model works in Docker container
3. **Commit and Push**: Commit all changes and push the branch

## Docker Deployment

To build and run with Docker:
```bash
cd defender
docker build -t extra_defence .
docker run -itp 8080:8080 extra_defence
```

**Note**: Ensure `model1_best.pickle` is included in the Docker image by:
- Adding to `defender/defender/models/` before building
- Or using a volume mount
- Or downloading during Docker build process

## Files Structure
```
extra_defence/
├── defender/
│   ├── defender/
│   │   ├── __main__.py          # Modified: Added Model1 loading
│   │   ├── models/
│   │   │   ├── __init__.py      # Modified: Added Model1 export
│   │   │   └── model1_rf_deep.py # New: Model1 implementation
│   ├── README.md                # Modified: Added Model1 usage
│   └── MODEL1_DOWNLOAD.md       # New: Download instructions
└── report.tex                   # New: Submission report
```

## Environment Variables

- `DF_MODEL_NAME`: Model to use (default: "model1")
- `DF_MODEL1_PATH`: Path to model1_best.pickle (default: "defender/models/model1_best.pickle")
- `DF_MODEL_THRESH`: Classification threshold (default: 0.5)

## Compatibility

- Compatible with existing defender infrastructure
- Uses EMBER feature extractor (v2) - same as EmberModel
- Follows same interface as other models (`predict()` method)
- Works with existing Flask app structure

## Notes

- Model file is NOT included in git (too large)
- Users must download model file separately
- Model uses scikit-learn RandomForest (no LightGBM dependency)
- All features extracted using EMBER v2 extractor (2381 dimensions)

