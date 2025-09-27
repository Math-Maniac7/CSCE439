# defender/models/my_ember2024_model.py
import os
import gzip
import logging
import numpy as np
import lightgbm as lgb

# Defaults (override via env if you want)
DEFAULT_MODEL_PATH = os.getenv("MODEL_PATH", "defender/models/pe_lgbm_ember.txt")
DEFAULT_THRESHOLD  = float(os.getenv("THRESHOLD", "0.974798")) 
ERROR_POLICY       = os.getenv("ERROR_POLICY", "benign").lower()

logging.basicConfig(level=logging.INFO)

class Ember2024LightGBMModel:
    def __init__(self,
                 model_path: str = DEFAULT_MODEL_PATH,
                 thresh: float = DEFAULT_THRESHOLD,
                 name: str = "ember2024-lgbm"):
        self.__name__ = name
        self.model_path = model_path
        self.thresh = float(thresh)

        # Load LightGBM booster exported by your trainer (text or gz)
        if model_path.endswith(".gz"):
            with gzip.open(model_path, "rb") as f:
                model_str = f.read().decode("utf-8")
            self.booster = lgb.Booster(model_str=model_str)
        else:
            self.booster = lgb.Booster(model_file=model_path)

        # Feature extractor (EMBER2024 v3 / thrember)
        try:
            from thrember import pe_v3  # provided by EMBER2024 install
        except Exception as e:
            raise RuntimeError(
                "Failed to import thrember. Install EMBER2024 (e.g., `pip install .` "
                "from the repo root) so `thrember` is available."
            ) from e
        self._extract_from_bytes = pe_v3.feature_vector_from_bytes

        # Fail fast if feature dims don’t match model
        want = int(self.booster.num_feature())
        try:
            tmp = np.asarray(self._extract_from_bytes(b"MZ"), dtype=np.float32).reshape(1, -1)
        except Exception:
            tmp = None
        if tmp is not None and tmp.shape[1] != want:
            raise RuntimeError(f"Model expects {want} features but extractor returns {tmp.shape[1]}.")

        logging.info(f"Loaded booster '{self.model_path}', threshold={self.thresh:.6f}, "
                     f"num_features={self.booster.num_feature()}")

    def predict(self, bytez: bytes) -> int:
        score = self.predict_proba(bytez)
        return int(score > self.thresh)

    def predict_proba(self, bytez: bytes) -> float:
        try:
            X = self._featurize(bytez)  # (1, D) float32
            want = int(self.booster.num_feature())
            if X.ndim != 2 or X.shape[0] != 1 or X.shape[1] != want:
                raise ValueError(f"Feature shape mismatch: got {X.shape}, want (1,{want})")
            p = float(self.booster.predict(X)[0])
            return 0.0 if p < 0.0 else (1.0 if p > 1.0 else p)  # clamp defensively
        except Exception as e:
            logging.warning(f"[predict_proba] extraction/predict failed: {e!r}")
            return 0.0 if ERROR_POLICY == "benign" else 1.0

    def model_info(self) -> dict:
        return {"name": self.__name__, "thresh": self.thresh, "model_path": self.model_path}

    def _featurize(self, bytez: bytes) -> np.ndarray:
        v = self._extract_from_bytes(bytez)   # 1D float32 vector (v3)
        return np.asarray(v, dtype=np.float32).reshape(1, -1)
