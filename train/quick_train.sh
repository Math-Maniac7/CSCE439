#!/bin/bash
# 快速训练和测试脚本

cd "$(dirname "$0")/.."

# 一行命令：训练模型并在测试集上评估
python3 train/train_ember_jsonl.py --train-dir /Users/felix/Documents/704/dataset/ember2018 --test-dir /Users/felix/Documents/704/dataset/ember2018 --output defender/defender/models/ember_jsonl_model.pickle --max-samples 50000

