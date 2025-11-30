# Model1 Download Instructions

## Overview
Model1 RandomForest Deep requires the trained model file `model1_best.pickle` to be downloaded separately before use.

## Download Location

**Model File URL:** https://drive.google.com/file/d/1GEsn_imO1m1c4on5UiJmP0S7Ku8PkqJu/view?usp=sharing

**Direct Download:** To download directly via command line:
```bash
gdown https://drive.google.com/uc?id=1GEsn_imO1m1c4on5UiJmP0S7Ku8PkqJu -O defender/defender/models/model1_best.pickle
```

Or download manually from the link above and place it at:
```
defender/defender/models/model1_best.pickle
```

**Note:** You may need to install `gdown` first: `pip install gdown`

## Model Details

- **File Name**: `model1_best.pickle`
- **File Size**: See Google Drive link for file size
- **Format**: Python pickle file containing:
  - `classifier`: RandomForestClassifier object (1500 trees, max depth 35)
  - `scaler`: MinMaxScaler object (optional)
  - `feature_names`: List of feature names (optional)

## Training Information

This model was trained using:
- **Dataset**: EMBER 2017, EMBER 2018, EMBER datasets
- **Training Samples**: 1,360,000 samples
- **Test Samples**: 440,000 samples
- **Performance**: 
  - Accuracy: 93.20%
  - Precision: 98.16%
  - Recall: 89.20%
  - F1-Score: 93.47%
  - AUC-ROC: 99.06%
  - False Positive Rate: 2.01%

## Verification

After downloading, verify the model can be loaded:

```bash
cd defender
python -m defender.models.model1_rf_deep defender/models/model1_best.pickle
```

This should print model information without errors.

## Alternative Installation

If you have the model file in a different location, you can specify the path:

```bash
export DF_MODEL1_PATH=/path/to/model1_best.pickle
python -m defender
```

