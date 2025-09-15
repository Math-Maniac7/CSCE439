from flask import Flask, jsonify, request
import time
import traceback

def create_app(model):
    app = Flask(__name__)
    app.config['model'] = model

    @app.route('/', methods=['POST'])
    def post():
        """Analyze a PE sample"""
        start_time = time.time()
        
        # Validate content type
        content_type = request.headers.get('Content-Type', '')
        if content_type != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            return resp

        # Get file bytes
        bytez = request.data
        
        # Basic validation
        if len(bytez) == 0:
            resp = jsonify({'error': 'empty file'})
            resp.status_code = 400
            return resp
        
        # Check file size limit (challenge requirement: reasonable limits)
        if len(bytez) > 100 * 1024 * 1024:  # 100MB limit
            resp = jsonify({'error': 'file too large'})
            resp.status_code = 413  # Payload Too Large
            return resp

        try:
            # Get model from app config
            model = app.config['model']

            # Query the model with error handling
            result = model.predict(bytez)
            
            # Validate result type and range
            if not isinstance(result, (int, float)) or result not in {0, 1}:
                print(f"Invalid model result: {result} (type: {type(result)})")
                resp = jsonify({'error': 'unexpected model result (not in [0,1])'})
                resp.status_code = 500  # Internal Server Error
                return resp

            # Ensure result is an integer
            result = int(result)
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Log warning if processing is slow (challenge constraint: 5 seconds)
            if processing_time > 4.0:
                print(f"Warning: Processing took {processing_time:.2f} seconds")

            # Return successful result
            resp = jsonify({
                'result': result,
                'processing_time': round(processing_time, 3)
            })
            resp.status_code = 200
            return resp
            
        except Exception as e:
            # Log the error for debugging
            print(f"Error during prediction: {e}")
            print(traceback.format_exc())
            
            # Calculate processing time even for errors
            processing_time = time.time() - start_time
            
            # Return error response
            resp = jsonify({
                'error': 'prediction failed',
                'processing_time': round(processing_time, 3)
            })
            resp.status_code = 500  # Internal Server Error
            return resp

    @app.route('/model', methods=['GET'])
    def get_model():
        """Get model information"""
        try:
            model_info = app.config['model'].model_info()
            resp = jsonify(model_info)
            resp.status_code = 200
            return resp
        except Exception as e:
            print(f"Error getting model info: {e}")
            resp = jsonify({'error': 'unable to get model information'})
            resp.status_code = 500
            return resp

    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        try:
            model = app.config.get('model')
            is_healthy = model is not None
            
            return jsonify({
                'status': 'healthy' if is_healthy else 'unhealthy',
                'model_loaded': is_healthy
            })
        except Exception as e:
            print(f"Health check error: {e}")
            return jsonify({
                'status': 'unhealthy',
                'error': str(e)
            }), 500

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'endpoint not found'}), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify({'error': 'method not allowed'}), 405

    @app.errorhandler(413)
    def payload_too_large(error):
        return jsonify({'error': 'file too large'}), 413

    return app