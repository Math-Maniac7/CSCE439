import os
import sys
import envparse

# Add the parent directory to Python path to fix imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # This goes up to /app/defender
root_dir = os.path.dirname(parent_dir)     # This goes up to /app

sys.path.insert(0, root_dir)
sys.path.insert(0, parent_dir)

# Now import with correct paths
from apps import create_app

# Import models with relative paths
from models.ember_model import StatefulNNEmberModel
from models.nfs_behemot_model import NFSBehemotModel
from models.nfs_commite_model import NFSCommiteBehemotModel
from models.nfs_model import PEAttributeExtractor, NFSModel, NeedForSpeedModel

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
    print(f"Python path: {sys.path[:3]}")  # Show first 3 paths
    
    # Check what model files are available
    models_dir = os.path.join(os.path.dirname(__file__), "models")
    print(f"Looking for models in: {models_dir}")
    
    if os.path.exists(models_dir):
        model_files = os.listdir(models_dir)
        print(f"Available model files: {model_files}")
    else:
        print("❌ Models directory not found!")
        # List all directories to debug
        print("Available directories:")
        for item in os.listdir(os.path.dirname(__file__)):
            item_path = os.path.join(os.path.dirname(__file__), item)
            if os.path.isdir(item_path):
                print(f"  📁 {item}")

    # Try to load your best model first, with fallbacks
    try:
        # First try the full NFS model
        nfs_full_path = os.path.join(models_dir, "nfs_full.pickle")
        if os.path.exists(nfs_full_path):
            print(f"✅ Loading NFS full model from: {nfs_full_path}")
            model = NFSModel(open(nfs_full_path, "rb"))
        else:
            # Try nfs_full.zip
            nfs_zip_path = os.path.join(models_dir, "nfs_full.zip")
            if os.path.exists(nfs_zip_path):
                print(f"📦 Extracting model from: {nfs_zip_path}")
                import zipfile
                with zipfile.ZipFile(nfs_zip_path, 'r') as zip_ref:
                    zip_ref.extractall(models_dir)
                # Try loading the extracted file
                if os.path.exists(nfs_full_path):
                    print(f"✅ Loading extracted NFS model")
                    model = NFSModel(open(nfs_full_path, "rb"))
                else:
                    raise FileNotFoundError("Model not found after extraction")
            else:
                # Try alternative model
                alt_files = [f for f in os.listdir(models_dir) if f.endswith('.pickle')]
                if alt_files:
                    alt_path = os.path.join(models_dir, alt_files[0])
                    print(f"✅ Loading alternative model: {alt_files[0]}")
                    model = NFSModel(open(alt_path, "rb"))
                else:
                    print("⚠️  No pickle files found, using NFSBehemotModel as fallback")
                    model = NFSBehemotModel()
                
    except Exception as e:
        print(f"❌ Error loading models: {e}")
        print("⚠️  Using OptimizedNFSModel as final fallback")
        from apps import OptimizedNFSModel
        model = OptimizedNFSModel()

    # Create Flask app
    print("🔧 Creating Flask application...")
    app = create_app(model)

    # Get port from command line or default to 8080
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
