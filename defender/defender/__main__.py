import os
import envparse
from defender.apps import create_app

# CUSTOMIZE: import model to be used
from defender.models.ember_model import StatefulNNEmberModel
from defender.models.nfs_behemot_model import NFSBehemotModel
from defender.models.nfs_commite_model import NFSCommiteBehemotModel
from defender.models.nfs_model import PEAttributeExtractor, NFSModel, NeedForSpeedModel

if __name__ == "__main__":
    # retrieve config values from environment variables
    model_gz_path = envparse.env("DF_MODEL_GZ_PATH", cast=str, default="models/ember_model.txt.gz")
    model_thresh = envparse.env("DF_MODEL_THRESH", cast=float, default=0.8336)
    model_name = envparse.env("DF_MODEL_NAME", cast=str, default="ember")
    model_ball_thresh = envparse.env("DF_MODEL_BALL_THRESH", cast=float, default=0.25)
    model_max_history = envparse.env("DF_MODEL_HISTORY", cast=int, default=10_000)

    # construct absolute path to ensure the correct model is loaded
    if not model_gz_path.startswith(os.sep):
        model_gz_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), model_gz_path)

    print("🚀 Starting malware defense service...")
    print(f"Working directory: {os.getcwd()}")
    print(f"Script location: {os.path.dirname(os.path.abspath(__file__))}")
    
    # FIXED: Check what model files are available - corrected path for nested structure
    models_dir = os.path.join(os.path.dirname(__file__), "models")  # Changed from "defender/models"
    print(f"Looking for models in: {models_dir}")
    
    if os.path.exists(models_dir):
        model_files = os.listdir(models_dir)
        print(f"Available model files: {model_files}")
    else:
        print("❌ Models directory not found!")
        # Also try absolute path
        abs_models_dir = os.path.join("/app", "defender", "defender", "models")
        print(f"Trying absolute path: {abs_models_dir}")
        if os.path.exists(abs_models_dir):
            models_dir = abs_models_dir
            model_files = os.listdir(models_dir)
            print(f"Found models at absolute path: {model_files}")

    # CUSTOMIZE: app and model instance
    # Try to load your best model first, with fallbacks
    try:
        # FIXED: First try the full NFS model - corrected paths
        nfs_full_path = os.path.join(models_dir, "nfs_full.pickle")  # Simplified path
        if os.path.exists(nfs_full_path):
            print(f"✅ Loading NFS full model from: {nfs_full_path}")
            model = NFSModel(open(nfs_full_path, "rb"))
        else:
            # Try alternative path
            nfs_alt_path = os.path.join(models_dir, "nfs_libraries_functions_nostrings.pickle")
            if os.path.exists(nfs_alt_path):
                print(f"✅ Loading NFS alternative model from: {nfs_alt_path}")
                model = NFSModel(open(nfs_alt_path, "rb"))
            else:
                # Try checking if nfs_full.zip exists and needs to be extracted
                nfs_zip_path = os.path.join(models_dir, "nfs_full.zip")
                if os.path.exists(nfs_zip_path):
                    print(f"Found zipped model: {nfs_zip_path}")
                    import zipfile
                    with zipfile.ZipFile(nfs_zip_path, 'r') as zip_ref:
                        zip_ref.extractall(models_dir)
                    # Try loading again
                    if os.path.exists(nfs_full_path):
                        print(f"✅ Loading extracted NFS model from: {nfs_full_path}")
                        model = NFSModel(open(nfs_full_path, "rb"))
                    else:
                        raise FileNotFoundError("NFS model not found after extraction")
                else:
                    # Use NFS Behemot as fallback
                    print("⚠️  Using NFSBehemotModel as fallback")
                    model = NFSBehemotModel()
                
    except Exception as e:
        print(f"❌ Error loading models: {e}")
        print("⚠️  Using NFSBehemotModel as final fallback")
        model = NFSBehemotModel()

    # Create Flask app
    print("🔧 Creating Flask application...")
    app = create_app(model)

    # Get port from command line or default to 8080
    import sys
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080

    print(f"🌐 Starting server on port {port}")
    print("📋 Competition requirements:")
    print("   - Memory usage ≤ 1GB")
    print("   - Response time ≤ 5 seconds") 
    print("   - FPR ≤ 1%, TPR ≥ 95%")
    print()
    print(f"🧪 Test with: curl -XPOST --data-binary @sample.exe http://127.0.0.1:{port}/ -H \"Content-Type: application/octet-stream\"")

    # Use gevent for better performance
    try:
        from gevent.pywsgi import WSGIServer
        print("✅ Using gevent WSGI server for optimal performance")
        http_server = WSGIServer(('0.0.0.0', port), app)
        http_server.serve_forever()
    except ImportError:
        print("⚠️  gevent not available, using Flask dev server")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
