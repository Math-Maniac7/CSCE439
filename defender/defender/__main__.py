import os
import sys
import envparse
from defender.apps import create_app

# Import available models
try:
    from defender.models.nfs_model import PEAttributeExtractor, NFSModel, NeedForSpeedModel
    HAS_NFS_MODEL = True
except ImportError as e:
    print(f"Warning: Could not import NFS models: {e}")
    HAS_NFS_MODEL = False

try:
    from defender.models.dummy_model import DummyModel
    HAS_DUMMY_MODEL = True
except ImportError as e:
    print(f"Warning: Could not import DummyModel: {e}")
    HAS_DUMMY_MODEL = False

try:
    from defender.models.lgbm_model import LGBMModel
    HAS_LGB_MODEL = True
except ImportError as e:
    print(f"Warning: Could not import LGBMModel: {e}")
    HAS_LGB_MODEL = False

# Try to import other models if they exist
try:
    from defender.models.nfs_behemot_model import NFSBehemotModel
    HAS_BEHEMOT_MODEL = True
except ImportError:
    HAS_BEHEMOT_MODEL = False

if __name__ == "__main__":
    # Retrieve config values from environment variables
    model_gz_path = envparse.env("DF_MODEL_GZ_PATH", cast=str, default="models/nfs_full.pickle")
    model_thresh = envparse.env("DF_MODEL_THRESH", cast=float, default=0.8336)
    model_name = envparse.env("DF_MODEL_NAME", cast=str, default="lgb")
    model_ball_thresh = envparse.env("DF_MODEL_BALL_THRESH", cast=float, default=0.25)
    model_max_history = envparse.env("DF_MODEL_HISTORY", cast=int, default=10_000)

    lgb_model_path = envparse.env("DF_LGB_MODEL_PATH", cast=str, default="models/pe_lgbm_ember.pkl")
    lgb_threshold  = envparse.env("DF_LGB_THRESHOLD", cast=float, default=None)
    lgb_nfeat      = envparse.env("DF_LGB_NFEATURES", cast=int, default=0)

    # Normalize paths relative to this file
    def _abs_path(p: str) -> str:
        if os.path.isabs(p):
            return p
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), p)

    model_gz_path = _abs_path(model_gz_path)
    lgb_model_path = _abs_path(lgb_model_path)

    print(f"Looking for model: {model_name}")
    print(f"NFS model path: {model_gz_path}")
    print(f"LGB model path: {lgb_model_path}")

    # Initialize model variable
    model = None

    # Try to load the specified model based on model_name
    if model_name.lower() in ("lgb", "lightgbm") and HAS_LGB_MODEL:
        try:
            if os.path.exists(lgb_model_path):
                print(f"Loading LGBMModel from {lgb_model_path}")
                with open(lgb_model_path, "rb") as f:
                    model = LGBMModel(f)
                if lgb_threshold is not None:
                    model.threshold = float(lgb_threshold)
                    print(f"Overriding threshold from env: {model.threshold}")
                if lgb_nfeat > 0 and getattr(model, "n_features", None) is None:
                    model.n_features = int(lgb_nfeat)
                    print(f"Setting n_features from env: {model.n_features}")
                print("LGBMModel loaded successfully")
            else:
                print(f"Model file not found: {lgb_model_path}")
        except Exception as e:
            print(f"Error loading LGBMModel: {e}")

    elif model_name.lower() == "nfs" and HAS_NFS_MODEL:
        try:
            if os.path.exists(model_gz_path):
                print(f"Loading NFSModel from {model_gz_path}")
                with open(model_gz_path, "rb") as f:
                    model = NFSModel(f)
                print("NFSModel loaded successfully")
            else:
                print(f"Model file not found: {model_gz_path}")
        except Exception as e:
            print(f"Error loading NFSModel: {e}")
    
    elif model_name.lower() == "behemot" and HAS_BEHEMOT_MODEL:
        try:
            print("Loading NFSBehemotModel")
            model = NFSBehemotModel()
            print("NFSBehemotModel loaded successfully")
        except Exception as e:
            print(f"Error loading NFSBehemotModel: {e}")

    # Fallback to dummy model if main model fails
    if model is None:
        if HAS_DUMMY_MODEL:
            print("Using DummyModel as fallback")
            model = DummyModel(thresh=model_thresh, name="dummy_fallback")
        else:
            print("ERROR: No models available!")
            # Create a minimal fallback model
            class MinimalModel:
                def predict(self, bytez):
                    return 1  # Default to malware
                def model_info(self):
                    return {"name": "minimal_fallback", "type": "emergency_fallback"}
            model = MinimalModel()
            print("Using minimal emergency fallback model")

    # Create Flask app
    app = create_app(model)

    # Get port from command line or use default
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080
    
    print(f"Starting server on port {port}")
    print(f"Model info: {model.model_info()}")
    print("Send PE files with: curl -XPOST --data-binary @file.exe http://127.0.0.1:8080/ -H \"Content-Type: application/octet-stream\"")

    # Start the server
    from gevent.pywsgi import WSGIServer
    http_server = WSGIServer(('', port), app)
    print("Server starting...")
    http_server.serve_forever()