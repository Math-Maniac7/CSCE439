#!/bin/bash
# SLURM作业脚本 - 训练5个防御模型
# 使用GPU和大量内存资源

#SBATCH --job-name=defence_training
#SBATCH --output=/scratch/user/yafeili/704/defenceOutput/slurm_training_%j.out
#SBATCH --error=/scratch/user/yafeili/704/defenceOutput/slurm_training_%j.err
#SBATCH --time=48:00:00          # 48小时时间限制（根据实际需要调整）
#SBATCH --nodes=1                # 使用1个节点
#SBATCH --ntasks-per-node=1      # 每个节点1个任务
#SBATCH --cpus-per-task=32       # 32个CPU核心
#SBATCH --mem=256G               # 256GB内存
#SBATCH --gres=gpu:1             # 1块GPU
#SBATCH --partition=gpu          # GPU分区（根据FASTER实际分区名称调整）

# 打印作业信息
echo "=========================================="
echo "Job ID: $SLURM_JOB_ID"
echo "Job Name: $SLURM_JOB_NAME"
echo "Node: $SLURM_NODELIST"
echo "Start time: $(date)"
echo "Working directory: $(pwd)"
echo "=========================================="

# 加载模块
module purge
module load GCCcore/12.2.0
module load Python/3.10.8
module load CUDA/11.7.0
module load cuDNN/8.4.1.50-CUDA-11.7.0  # 如果可用

# 显示已加载的模块
echo ""
echo "Loaded modules:"
module list

# 设置CUDA设备
export CUDA_VISIBLE_DEVICES=0

# 设置性能优化环境变量
export OMP_NUM_THREADS=32
export MKL_NUM_THREADS=32
export NUMEXPR_NUM_THREADS=32

# 激活虚拟环境（尝试多个可能的位置）
VENV_ACTIVATED=0

if [ -f ~/venv/bin/activate ]; then
    source ~/venv/bin/activate
    echo "Activated virtual environment: ~/venv"
    VENV_ACTIVATED=1
elif [ -f $SCRATCH/venv/bin/activate ]; then
    source $SCRATCH/venv/bin/activate
    echo "Activated virtual environment: $SCRATCH/venv"
    VENV_ACTIVATED=1
elif [ -f "/scratch/user/yafeili/venv/bin/activate" ]; then
    source /scratch/user/yafeili/venv/bin/activate
    echo "Activated virtual environment: /scratch/user/yafeili/venv"
    VENV_ACTIVATED=1
fi

if [ $VENV_ACTIVATED -eq 0 ]; then
    echo "Warning: Virtual environment not found, using system Python"
    echo "建议：创建虚拟环境以确保所有依赖已安装"
    echo "      python3 -m venv ~/venv"
    echo "      source ~/venv/bin/activate"
    echo "      pip install numpy pandas scikit-learn tqdm lightgbm pefile lief requests"
    echo "      pip install git+https://github.com/endgameinc/ember.git"
fi

# 验证Python和GPU
echo ""
echo "Python version: $(python3 --version)"
echo "Python path: $(which python3)"
echo ""
echo "GPU status:"
nvidia-smi

# 进入项目目录（尝试多个可能的路径）
if [ -d "/scratch/user/yafeili/CSCE439" ]; then
    cd /scratch/user/yafeili/CSCE439
elif [ -d "/scratch/user/yafeili/704/CSCE439" ]; then
    cd /scratch/user/yafeili/704/CSCE439
elif [ -d "$SCRATCH/CSCE439" ]; then
    cd $SCRATCH/CSCE439
else
    echo "错误: 找不到项目目录"
    echo "尝试查找CSCE439目录..."
    find $SCRATCH -name "CSCE439" -type d 2>/dev/null | head -1 | xargs cd
    if [ $? -ne 0 ]; then
        echo "错误: 无法找到项目目录，请检查路径"
        exit 1
    fi
fi

echo ""
echo "Working directory: $(pwd)"
echo ""

# 检查数据集目录（尝试多个可能的路径）
echo "Checking dataset directories..."
if [ -d "/scratch/user/yafeili/704/dataset" ]; then
    DATASET_BASE="/scratch/user/yafeili/704/dataset"
elif [ -d "/scratch/user/yafeili/dataset" ]; then
    DATASET_BASE="/scratch/user/yafeili/dataset"
else
    echo "警告: 找不到数据集基础目录"
    DATASET_BASE="/scratch/user/yafeili/704/dataset"
fi

echo "Dataset base directory: $DATASET_BASE"
[ -d "$DATASET_BASE/ember_2017_2" ] && echo "✓ ember_2017_2 exists" || echo "✗ ember_2017_2 not found"
[ -d "$DATASET_BASE/ember2018" ] && echo "✓ ember2018 exists" || echo "✗ ember2018 not found"
[ -d "$DATASET_BASE/ember" ] && echo "✓ ember exists" || echo "✗ ember not found"
[ -d "$DATASET_BASE/challenge_ds" ] && echo "✓ challenge_ds exists" || echo "✗ challenge_ds not found"
echo ""

# 运行训练（非交互式，自动确认）
echo "=========================================="
echo "Starting training..."
echo "=========================================="
echo ""

# 使用echo "y"自动确认，避免交互式提示
echo "y" | bash train/train_all_models.sh

# 检查训练结果
TRAIN_EXIT_CODE=$?

echo ""
echo "=========================================="
echo "Training completed!"
echo "Exit code: $TRAIN_EXIT_CODE"
echo "End time: $(date)"
echo "=========================================="

# 显示输出目录内容
echo ""
echo "Output directory contents:"
ls -lht /scratch/user/yafeili/704/defenceOutput/ | head -20

exit $TRAIN_EXIT_CODE

