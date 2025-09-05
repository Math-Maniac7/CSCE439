import os
import numpy as np
import pefile
from ember import PEFeatureExtractor
import lightgbm as lgb
import joblib

EMBER_MODEL_PATH = "ember_lgbm.model"
EMBER_FEAT_PATH = "ember_features.npy"
EMBER_LABEL_PATH = "ember_labels.npy"

# 1. EMBER feature extraction
class EmberModel:
    def __init__(self, model_path=EMBER_MODEL_PATH):
        self.model = lgb.Booster(model_file=model_path)
        self.extractor = PEFeatureExtractor(feature_version=2)

    def extract(self, bytez):
        # Save to temp file for pefile/ember
        with open("_tmp_pe.bin", "wb") as f:
            f.write(bytez)
        feats = self.extractor.process_pe("_tmp_pe.bin")
        os.remove("_tmp_pe.bin")
        return np.array(feats, dtype=np.float32)

    def predict_proba(self, bytez):
        feats = self.extract(bytez)
        return float(self.model.predict(feats.reshape(1, -1))[0])

# 2. Training script for EMBER+LightGBM
if __name__ == "__main__":
    # Example: load features/labels, train, save model
    X = np.load(EMBER_FEAT_PATH)
    y = np.load(EMBER_LABEL_PATH)
    dtrain = lgb.Dataset(X, label=y)
    params = dict(objective="binary", metric="auc", num_leaves=64, learning_rate=0.05, n_jobs=2)
    model = lgb.train(params, dtrain, num_boost_round=200)
    model.save_model(EMBER_MODEL_PATH)
    print("EMBER LightGBM model trained and saved.")
