import os
from envparse import env
from defender.apps import create_app

# CUSTOMIZE: import model to be used
from defender.models.lgbm_model import Ember2024LightGBMModel

if __name__ == "__main__":
    # retrive config values from environment variables
    model_path = env("MODEL_PATH", cast=str, default="models/pe_lgbm_ember.txt")
    threshold  = env("THRESHOLD", cast=float, default=0.974798)
    model_name = env("MODEL_NAME", cast=str, default="ember2024-lgbm")

    # construct absolute path to ensure the correct model is loaded
    if not os.path.isabs(model_path):
        here = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(here, model_path)

    # CUSTOMIZE: app and model instance
    model = Ember2024LightGBMModel(model_path=model_path, thresh=threshold, name=model_name)

    app = create_app(model)

    import sys
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080

    from gevent.pywsgi import WSGIServer
    http_server = WSGIServer(('', port), app)
    http_server.serve_forever()

    # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
