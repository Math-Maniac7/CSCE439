#!/bin/bash
# HPRC超算训练脚本
# 使用GPU和充分利用内存资源

#SBATCH --job-name=ember_training
#SBATCH --output=ember_training_%j.out
#SBATCH --error=ember_training_%j.err
#SBATCH --time=24:00:00
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=256G
#SBATCH --gres=gpu:1

# 加载模块（根据HPRC配置调整）
module load Python/3.9.6-GCCcore-11.2.0
module load CUDA/11.7.0

# 激活虚拟环境（如果有）
# source venv/bin/activate

# 安装依赖（如果需要）
# pip install --user lightgbm numpy pandas scikit-learn tqdm
# pip install --user git+https://github.com/endgameinc/ember.git

# 设置CUDA设备
export CUDA_VISIBLE_DEVICES=0

# 运行训练（充分利用GPU和内存）
cd $SLURM_SUBMIT_DIR

python3 train/train_ember_jsonl.py \
    --train-dir /path/to/ember2018 \
    --test-dir /path/to/ember2018 \
    --output defender/defender/models/ember_jsonl_model.pickle \
    --use-gpu \
    --n-estimators 1000 \
    --no-memory-limit \
    --sample-ratio 1.0

echo "Training completed!"

