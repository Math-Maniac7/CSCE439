import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

# 1D CNN for raw byte malware detection (MalConv-style, simplified)
class MalConv(nn.Module):
    def __init__(self, input_length=200*1024, emb_dim=8, n_classes=1):
        super().__init__()
        self.input_length = input_length
        self.embedding = nn.Embedding(257, emb_dim, padding_idx=256)  # 0-255 bytes + 1 pad
        self.conv1 = nn.Conv1d(emb_dim, 128, kernel_size=512, stride=512)
        self.conv2 = nn.Conv1d(128, 128, kernel_size=7, stride=1, padding=3)
        self.fc = nn.Linear(128, n_classes)

    def forward(self, x):
        # x: (batch, seq_len)
        x = self.embedding(x)  # (batch, seq_len, emb_dim)
        x = x.permute(0, 2, 1)  # (batch, emb_dim, seq_len)
        x = F.relu(self.conv1(x))
        x = F.relu(self.conv2(x))
        x = F.adaptive_max_pool1d(x, 1).squeeze(-1)  # (batch, 128)
        x = self.fc(x)
        return torch.sigmoid(x).squeeze(-1)

# Inference wrapper
class MalConvPredictor:
    def __init__(self, model_path, input_length=200*1024, device='cpu'):
        self.model = MalConv(input_length=input_length)
        self.model.load_state_dict(torch.load(model_path, map_location=device))
        self.model.eval()
        self.input_length = input_length
        self.device = device

    def preprocess(self, bytez):
        arr = np.frombuffer(bytez[:self.input_length], dtype=np.uint8)
        if len(arr) < self.input_length:
            arr = np.pad(arr, (0, self.input_length - len(arr)), constant_values=256)
        arr = arr[:self.input_length]
        return torch.tensor(arr, dtype=torch.long).unsqueeze(0)

    def predict_proba(self, bytez):
        x = self.preprocess(bytez).to(self.device)
        with torch.no_grad():
            proba = float(self.model(x).cpu().numpy()[0])
        return proba

# Training script would be separate, not included here for brevity
