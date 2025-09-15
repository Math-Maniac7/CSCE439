#!/usr/bin/env python3
"""
Flask application for malware detection competition
Memory ≤ 1GB, Response time ≤ 5 seconds, FPR ≤ 1%, TPR ≥ 95%
"""

import os
import sys
import time
import pickle
import traceback
from flask import Flask, jsonify, request
import envparse

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import your available models (remove the problematic final_optimized_model import)
try:
    from models.final_optimized_model import CompetitionNFSModel, OptimizedNFSModel
except ImportError:
    # Fallback: Create compatible wrapper classes for your existing models
    print("Warning: final_optimized_model not found, using fallback implementations")
    
    class CompetitionNFSModel:
        def __init__(self, model_file_or_object):
            if hasattr(model_file_or_object, 'read'):  # It's a file object
                self.model = pickle.load(model_file_or_object)
            else:
                self.model = model_file_or_object
        
        def predict(self, bytez):
            # Adapt to your model's predict method
            if hasattr(self.model, 'predict'):
                result = self.model.predict(bytez)
                # Ensure result is 0 or 1
                if isinstance(result, (list, tuple)):
                    result = int(result[0] > 0.5) if len(result) > 0 else 1
                elif isinstance(result, float):
                    result = int(result > 0.5)
                elif isinstance(result, bool):
                    result = int(result)
                return result
            return 1  # Default to malware if no predict method
        
        def model_info(self):
            return {
                "model_type": "CompetitionNFS",
                "status": "loaded"
            }
    
    class OptimizedNFSModel:
        def __init__(self):
            # This is a fallback model - you can implement basic logic here
            pass
        
        def predict(self, bytez):
            # Simple heuristic fallback
            # Check for common PE patterns
            if bytez.startswith(b'MZ') and len(bytez) > 1000:
                # Basic PE file detected, do simple checks
                if b'CreateFile' in bytez or b'WriteFile' in bytez:
                    return 1  # Potentially suspicious
                return 0  # Likely benign
            return 1  # Unknown format, assume malware
        
        def model_info(self):
            return {
                "model_type": "OptimizedNFS (Fallback)",
                "status": "fallback_active"
            }

def create_app(model):
    app = Flask(__name__)
    app.config['model'] = model
    app.config['request_count'] = 0
    app.config['total_time'] = 0.0
    
    @app.route('/', methods=['POST'])
    def predict_malware():
        """Main prediction endpoint for competition"""
        start_time = time.time()
        
        # Validate content type
        if request.headers.get('Content-Type') != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400
            return resp
        
        # Get file bytes
        bytez = request.data
        
        # Validate file size (basic sanity check)
        if len(bytez) < 100:  # Too small to be a valid PE
            resp = jsonify({'result': 0})  # Assume benign
            resp.status_code = 200
            return resp
        
        if len(bytez) > 100_000_000:  # > 100MB, probably not standard PE
            resp = jsonify({'result': 1})  # Assume malware (safer)
            resp.status_code = 200
            return resp
        
        try:
            # Get model and predict
            model = app.config['model']
            result = model.predict(bytez)
            
            # Validate result
            if not isinstance(result, int) or result not in {0, 1}:
                print(f"Warning: Invalid model result: {result}")
                result = 1  # Default to malware on error
            
            # Track performance metrics
            elapsed_time = time.time() - start_time
            app.config['request_count'] += 1
            app.config['total_time'] += elapsed_time
            
            # Log performance
            avg_time = app.config['total_time'] / app.config['request_count']
            print(f"Request {app.config['request_count']}: {elapsed_time:.3f}s (avg: {avg_time:.3f}s)")
            
            # Check if we're meeting time requirements
            if elapsed_time > 5.0:
                print(f"ERROR: Request exceeded 5 second limit: {elapsed_time:.3f}s")
            
            resp = jsonify({'result': result})
            resp.status_code = 200
            return resp
            
        except Exception as e:
            print(f"Prediction error: {e}")
            print(traceback.format_exc())
            
            # Return malware on error (safer for AV system)
            resp = jsonify({'result': 1})
            resp.status_code = 200  # Don't return 500, just default prediction
            return resp
    
    @app.route('/model', methods=['GET'])
    def get_model_info():
        """Get model information"""
        try:
            model = app.config['model']
            if hasattr(model, 'model_info'):
                info = model.model_info()
            else:
                info = {"model_type": "Unknown", "status": "loaded"}
            
            # Add performance stats
            if app.config['request_count'] > 0:
                info['avg_response_time'] = app.config['total_time'] / app.config['request_count']
                info['total_requests'] = app.config['request_count']
            
            resp = jsonify(info)
            resp.status_code = 200
            return resp
        except Exception as e:
            print(f"Model info error: {e}")
            resp = jsonify({'error': 'model info unavailable'})
            resp.status_code = 500
            return resp
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'requests_processed': app.config['request_count'],
            'avg_response_time': (app.config['total_time'] / app.config['request_count']) 
                               if app.config['request_count'] > 0 else 0
        })
    
    return app

def main():
    """Main application entry point - This is a fallback, use __main__.py instead"""
    print("Warning: Running apps.py directly. Use __main__.py for proper startup.")
    
    # Configuration from environment variables
    model_path = envparse.env("DF_MODEL_PATH", cast=str, 
                             default=os.path.join(os.path.dirname(__file__), "models/nfs_full.pickle"))
    port = envparse.env("DF_PORT", cast=int, default=8080)
    
    # Ensure model path is absolute
    if not model_path.startswith('/'):
        model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), model_path)
    
    print(f"Loading model from: {model_path}")
    
    try:
        # Load the competition model
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                model = CompetitionNFSModel(f)
        else:
            print(f"Warning: Model file not found at {model_path}")
            print("Using default model...")
            model = OptimizedNFSModel()
        
        print("Model loaded successfully!")
        if hasattr(model, 'model_info'):
            print(f"Model info: {model.model_info()}")
        
    except Exception as e:
        print(f"Error loading model: {e}")
        print("Using fallback model...")
        model = OptimizedNFSModel()
    
    # Create Flask app
    app = create_app(model)
    
    print(f"Starting server on port {port}...")
    print("Competition requirements:")
    print("- Memory usage ≤ 1GB")
    print("- Response time ≤ 5 seconds")
    print("- FPR ≤ 1%, TPR ≥ 95%")
    print()
    print("Test with: curl -XPOST --data-binary @sample.exe http://localhost:8080/ -H \"Content-Type: application/octet-stream\"")
    
    # Use gevent for better performance
    try:
        from gevent.pywsgi import WSGIServer
        http_server = WSGIServer(('0.0.0.0', port), app, log=None)
        http_server.serve_forever()
    except ImportError:
        print("Warning: gevent not available, using Flask dev server")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
