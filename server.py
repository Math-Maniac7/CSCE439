import os
import numpy as np
import torch
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn
from train_ember import EmberModel
from malconv import MalConvPredictor

EMBER_MODEL_PATH = "ember_lgbm.model"
MALCONV_MODEL_PATH = "malconv.pt"

# Load models at startup
ember = EmberModel(EMBER_MODEL_PATH)
malconv = MalConvPredictor(MALCONV_MODEL_PATH, input_length=200*1024, device='cpu')

app = FastAPI()

@app.post("/", response_class=JSONResponse)
async def detect(request: Request):
    bytez = await request.body()
    if not bytez or len(bytez) > 2*1024*1024:
        return JSONResponse({"result": 0}, status_code=400)
    # 1. EMBER+LightGBM
    ember_proba = ember.predict_proba(bytez)
    # 2. MalConv
    malconv_proba = malconv.predict_proba(bytez)
    # 3. Hybrid voting (weighted average, threshold at 0.5)
    # You can tune weights and threshold as needed
    fused = 0.7 * ember_proba + 0.3 * malconv_proba
    result = int(fused >= 0.5)
    return {"result": result}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, workers=1)
