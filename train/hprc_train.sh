#!/bin/bash
# HPRC FASTER超算训练脚本
# 使用GPU和充分利用内存资源

#SBATCH --job-name=ember_training
#SBATCH --output=ember_training_%j.out
#SBATCH --error=ember_training_%j.err
#SBATCH --time=24:00:00          # 24小时时间限制
#SBATCH --nodes=1                # 使用1个节点
#SBATCH --ntasks-per-node=1      # 每个节点1个任务
#SBATCH --cpus-per-task=32       # 32个CPU核心
#SBATCH --mem=256G               # 256GB内存
#SBATCH --gres=gpu:1             # 1块GPU
#SBATCH --partition=gpu          # GPU分区（根据FASTER实际分区名称调整）

# 打印作业信息
echo "=========================================="
echo "Job ID: $SLURM_JOB_ID"
echo "Node: $SLURM_NODELIST"
echo "Start time: $(date)"
echo "Working directory: $(pwd)"
echo "=========================================="

# 加载模块（根据FASTER实际模块名称调整）
module purge
module load GCCcore/12.2.0
module load Python/3.10.8
module load CUDA/11.7.0
module load cuDNN/8.4.1.50-CUDA-11.7.0

# 显示已加载的模块
echo "Loaded modules:"
module list

# 设置CUDA设备
export CUDA_VISIBLE_DEVICES=0

# 设置性能优化环境变量
export OMP_NUM_THREADS=32
export MKL_NUM_THREADS=32
export NUMEXPR_NUM_THREADS=32

# 激活虚拟环境（修改为你的实际路径）
# 如果虚拟环境在 $SCRATCH/ember_training/venv
if [ -f "$SCRATCH/ember_training/venv/bin/activate" ]; then
    source $SCRATCH/ember_training/venv/bin/activate
    echo "Virtual environment activated: $SCRATCH/ember_training/venv"
else
    echo "Warning: Virtual environment not found, using system Python"
fi

# 验证Python和GPU
echo "Python version: $(python3 --version)"
echo "Python path: $(which python3)"
echo "GPU status:"
nvidia-smi

# 设置工作目录（修改为你的实际项目路径）
cd $SCRATCH/CSCE439 || cd $SLURM_SUBMIT_DIR
echo "Working directory: $(pwd)"

# 运行训练（修改数据路径为你的实际路径）
echo "=========================================="
echo "Starting training..."
echo "=========================================="

python3 train/train_ember_jsonl.py \
    --train-dir $SCRATCH/datasets/ember2018 \
    --test-dir $SCRATCH/datasets/ember2018 \
    --output defender/defender/models/ember_jsonl_model.pickle \
    --use-gpu \
    --n-estimators 1000 \
    --no-memory-limit \
    --sample-ratio 1.0

TRAIN_EXIT_CODE=$?

echo "=========================================="
echo "End time: $(date)"
if [ $TRAIN_EXIT_CODE -eq 0 ]; then
    echo "Training completed successfully!"
else
    echo "Training failed with exit code: $TRAIN_EXIT_CODE"
fi
echo "=========================================="

