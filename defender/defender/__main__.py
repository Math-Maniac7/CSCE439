#!/usr/bin/env python3
"""
Simple main entry point that only uses the existing nfs_full.pickle model
"""

import os
import sys
import envparse

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import the simple NFS model
try:
    from simple_nfs_model import NFSModel
    print("✓ NFSModel imported successfully")
except ImportError as e:
    print(f"✗ Could not import NFSModel: {e}")
    sys.exit(1)

def main():
    print("=" * 60)
    print("PE Malware Defender - Simple NFS Model")
    print("=" * 60)
    
    # Get configuration
    model_path = envparse.env("DF_MODEL_GZ_PATH", cast=str, default="defender/models/nfs_full.pickle")
    
    # Make path absolute if relative
    if not os.path.isabs(model_path):
        model_path = os.path.join(current_dir, model_path)
    
    print(f"Model path: {model_path}")
    
    # Check if model file exists
    if not os.path.exists(model_path):
        print(f"✗ Model file not found: {model_path}")
        print("Please make sure nfs_full.pickle exists in the models folder")
        sys.exit(1)
    
    # Load the model
    try:
        print("Loading NFS model...")
        model = NFSModel(model_path=model_path)
        info = model.model_info()
        print(f"✓ Model loaded successfully: {info}")
        
        # Test the model with dummy data
        print("Testing model...")
        test_bytes = b'MZ' + b'\x00' * 1000  # Simple test PE-like data
        test_pred = model.predict(test_bytes)
        print(f"✓ Test prediction: {test_pred} ({'malware' if test_pred == 1 else 'benign'})")
        
    except Exception as e:
        print(f"✗ Error loading model: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Create Flask app
    try:
        from defender.apps import create_app
        app = create_app(model)
        print("✓ Flask app created successfully")
    except ImportError as e:
        print(f"✗ Error importing Flask app: {e}")
        print("Make sure the defender.apps module exists")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error creating Flask app: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Get port
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080
    
    print(f"\n{'='*60}")
    print(f"Server Starting")
    print(f"{'='*60}")
    print(f"Port: {port}")
    print(f"Model: {info['name']} ({info['classifier_type']})")
    print(f"Endpoint: http://127.0.0.1:{port}/")
    print(f"\nTest with:")
    print(f"  curl -XPOST --data-binary @your_file.exe \\")
    print(f"       http://127.0.0.1:{port}/ \\")
    print(f"       -H \"Content-Type: application/octet-stream\"")
    print(f"{'='*60}")

    # Start the server
    try:
        from gevent.pywsgi import WSGIServer
        http_server = WSGIServer(('', port), app)
        print(f"\n🚀 Server running on port {port}")
        print("Press Ctrl+C to stop")
        http_server.serve_forever()
        
    except ImportError:
        print("\n⚠️  gevent not available, using Flask development server")
        app.run(host='0.0.0.0', port=port, debug=False)
        
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except Exception as e:
        print(f"\n💥 Server error: {e}")

if __name__ == "__main__":
    main()
