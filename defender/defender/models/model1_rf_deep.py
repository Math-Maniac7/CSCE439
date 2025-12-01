"""
Model1 RandomForest Deep Model
Loads model1_best.pickle trained on EMBER dataset features
"""

import os
import pickle
import numpy as np
from ember import PEFeatureExtractor

MODEL1_DEFAULT_PATH = 'defender/models/model1_best.pickle'


class Model1_RandomForest_Deep(object):
    """
    RandomForest Deep model for malware detection
    Uses EMBER feature extractor and trained RandomForest classifier
    """
    
    def __init__(self, 
                 model_path: str = MODEL1_DEFAULT_PATH,
                 thresh: float = 0.5,
                 name: str = 'model1_rf_deep'):
        """
        Initialize Model1 RandomForest Deep model
        
        Args:
            model_path: Path to model1_best.pickle file
            thresh: Classification threshold (default 0.5)
            name: Model name
        """
        self.model_path = model_path
        self.thresh = thresh
        self.__name__ = name
        
        # Construct absolute path if relative
        if not os.path.isabs(model_path):
            # Try relative to models directory first
            models_dir = os.path.dirname(os.path.abspath(__file__))
            potential_path = os.path.join(models_dir, 'model1_best.pickle')
            if os.path.exists(potential_path):
                model_path = potential_path
            else:
                # Try relative to defender directory
                defender_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
                model_path = os.path.join(defender_dir, model_path)
        
        # Load the model
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model file not found: {model_path}\n"
                f"Please download model1_best.pickle and place it in defender/models/ directory.\n"
                f"See README.md for download instructions."
            )
        
        print(f"Loading Model1 RandomForest Deep from {model_path}")
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        
        # Extract components (format from train/model_definitions.py)
        if isinstance(model_data, dict):
            self.classifier = model_data.get('classifier')
            self.scaler = model_data.get('scaler')
            self.feature_names = model_data.get('feature_names')
        else:
            # Handle case where pickle directly contains classifier
            self.classifier = model_data
            self.scaler = None
            self.feature_names = None
        
        if self.classifier is None:
            raise ValueError("Model file does not contain a classifier")
        
        # Initialize EMBER feature extractor
        self.extractor = PEFeatureExtractor(2)  # feature_version=2
        
        print(f"Model1 RandomForest Deep loaded successfully")
        if self.scaler:
            print(f"  - Scaler: {type(self.scaler).__name__}")
        print(f"  - Classifier: {type(self.classifier).__name__}")
        if hasattr(self.classifier, 'n_estimators'):
            print(f"  - Number of trees: {self.classifier.n_estimators}")
        if hasattr(self.classifier, 'max_depth'):
            print(f"  - Max depth: {self.classifier.max_depth}")
    
    def predict(self, bytez: bytes) -> int:
        """
        Predict if bytez is malicious (1) or benign (0)
        
        Args:
            bytez: PE file bytes
        
        Returns:
            1 if malicious, 0 if benign
        """
        score = self.predict_proba(bytez)
        return int(score > self.thresh)
    
    def predict_proba(self, bytez: bytes) -> float:
        """
        Predict probability that bytez is malicious
        
        Args:
            bytez: PE file bytes
        
        Returns:
            Probability score between 0 and 1
        """
        # Extract EMBER features (2381 dimensions)
        features = np.array(self.extractor.feature_vector(bytez), dtype=np.float32)
        
        # Reshape to 2D array for prediction
        features = features.reshape(1, -1)
        
        # Apply scaler if available
        if self.scaler is not None:
            features = self.scaler.transform(features)
        
        # Predict probability of being malicious (class 1)
        proba = self.classifier.predict_proba(features)[0]
        
        # Return probability of malicious class
        if proba.ndim == 0:
            # Binary classification with predict_proba returning single value
            return float(proba)
        elif len(proba) == 2:
            # Two classes: [benign_prob, malicious_prob]
            return float(proba[1])
        else:
            # Single probability value
            return float(proba[0]) if proba[0] > 0.5 else float(1 - proba[0])
    
    def model_info(self) -> dict:
        """
        Return model information dictionary
        """
        info = {
            "name": self.__name__,
            "model_path": self.model_path,
            "thresh": self.thresh,
            "type": "RandomForest Deep",
            "feature_extractor": "EMBER v2"
        }
        
        if hasattr(self.classifier, 'n_estimators'):
            info["n_estimators"] = self.classifier.n_estimators
        if hasattr(self.classifier, 'max_depth'):
            info["max_depth"] = self.classifier.max_depth
        if self.scaler:
            info["scaler"] = type(self.scaler).__name__
        
        return info


if __name__ == '__main__':
    # Test loading the model
    import sys
    
    model_path = sys.argv[1] if len(sys.argv) > 1 else MODEL1_DEFAULT_PATH
    try:
        model = Model1_RandomForest_Deep(model_path=model_path)
        print("\nModel Info:")
        import json
        print(json.dumps(model.model_info(), indent=2))
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()



