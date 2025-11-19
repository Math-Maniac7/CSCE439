import os
import sys
import envparse
from defender.apps import create_app

# Import available models
try:
    from defender.models.ember_jsonl_model import EMBERJSONLModel
    HAS_EMBER_JSONL_MODEL = True
except ImportError as e:
    print(f"Warning: Could not import EMBERJSONLModel: {e}")
    HAS_EMBER_JSONL_MODEL = False

# Fallback dummy model
try:
    from defender.models.dummy_model import DummyModel
    HAS_DUMMY_MODEL = True
except ImportError as e:
    print(f"Warning: Could not import DummyModel: {e}")
    HAS_DUMMY_MODEL = False

if __name__ == "__main__":
    # Retrieve config values from environment variables
    model_gz_path = envparse.env("DF_MODEL_GZ_PATH", cast=str, default="models/ember_jsonl_model.pickle")
    model_thresh = envparse.env("DF_MODEL_THRESH", cast=float, default=0.5)
    model_name = envparse.env("DF_MODEL_NAME", cast=str, default="ember_jsonl")

    # Construct absolute path to ensure the correct model is loaded
    if not model_gz_path.startswith(os.sep):
        model_gz_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), model_gz_path)

    print(f"Looking for model: {model_name}")
    print(f"Model path: {model_gz_path}")

    # Initialize model variable
    model = None

    # Try to load the specified model based on model_name
    if model_name.lower() == "ember_jsonl" and HAS_EMBER_JSONL_MODEL:
        try:
            if os.path.exists(model_gz_path):
                print(f"Loading EMBERJSONLModel from {model_gz_path}")
                model = EMBERJSONLModel(model_path=model_gz_path, threshold=model_thresh)
                print("EMBERJSONLModel loaded successfully")
            else:
                print(f"Model file not found: {model_gz_path}")
        except Exception as e:
            print(f"Error loading EMBERJSONLModel: {e}")

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