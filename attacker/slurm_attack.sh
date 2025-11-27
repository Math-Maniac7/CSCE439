#!/bin/bash
# SLURM作业脚本 - 运行5种攻击方法
# 不需要GPU，只需要CPU和内存

#SBATCH --job-name=attack_methods
#SBATCH --output=/scratch/user/yafeili/704/attackOutput/slurm_attack_%j.out
#SBATCH --error=/scratch/user/yafeili/704/attackOutput/slurm_attack_%j.err
#SBATCH --time=24:00:00          # 24小时时间限制

# ---- CPU分区，不需要GPU ----
#SBATCH --partition=cpu          # CPU分区
#SBATCH --nodes=1               # 使用1个节点
#SBATCH --ntasks-per-node=1     # 每个节点1个任务
#SBATCH --cpus-per-task=16      # 16个CPU核心（攻击方法可以并行处理）
#SBATCH --mem=32G               # 32GB内存（足够处理大量样本）

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

# 显示已加载的模块
echo ""
echo "Loaded modules:"
module list

# 设置性能优化环境变量（匹配CPU核心数）
export OMP_NUM_THREADS=16
export MKL_NUM_THREADS=16
export NUMEXPR_NUM_THREADS=16

# ==================== 设置临时目录（避免home目录磁盘配额问题）====================
export TMPDIR="$SCRATCH/tmp"
export TMP="$SCRATCH/tmp"
export TEMPDIR="$SCRATCH/tmp"

# 创建临时目录（如果不存在）
mkdir -p "$TMPDIR"
echo "✓ 临时目录设置为: $TMPDIR"
echo "  这会避免home目录磁盘配额问题"
echo ""

# 激活虚拟环境（尝试多个可能的位置）
VENV_ACTIVATED=0

# 按优先级尝试激活虚拟环境
if [ -f ~/venv/bin/activate ]; then
    source ~/venv/bin/activate
    echo "✓ Activated virtual environment: ~/venv"
    VENV_ACTIVATED=1
elif [ -f /scratch/user/yafeili/venv/bin/activate ]; then
    source /scratch/user/yafeili/venv/bin/activate
    echo "✓ Activated virtual environment: /scratch/user/yafeili/venv"
    VENV_ACTIVATED=1
elif [ -f $SCRATCH/venv/bin/activate ]; then
    source $SCRATCH/venv/bin/activate
    echo "✓ Activated virtual environment: $SCRATCH/venv"
    VENV_ACTIVATED=1
fi

if [ $VENV_ACTIVATED -eq 0 ]; then
    echo "⚠ Warning: Virtual environment not found, using system Python"
    echo ""
    echo "建议：创建虚拟环境以确保所有依赖已安装"
    echo "  在登录节点运行："
    echo "    module load GCCcore/12.2.0 Python/3.10.8"
    echo "    python3 -m venv ~/venv"
    echo "    source ~/venv/bin/activate"
    echo "    pip install --upgrade pip"
    echo "    pip install numpy pefile tqdm"
    echo ""
    echo "继续使用系统Python（可能缺少某些依赖）..."
fi

# 验证Python
echo ""
echo "Python version: $(python3 --version)"
echo "Python path: $(which python3)"
echo ""

# 进入项目目录
PROJECT_DIR="/scratch/user/yafeili/CSCE439"
if [ -d "$PROJECT_DIR" ]; then
    cd "$PROJECT_DIR"
    echo "✓ 进入项目目录: $PROJECT_DIR"
else
    echo "错误: 项目目录不存在: $PROJECT_DIR"
    echo "尝试查找CSCE439目录..."
    FOUND_DIR=$(find $SCRATCH -name "CSCE439" -type d 2>/dev/null | head -1)
    if [ -n "$FOUND_DIR" ] && [ -d "$FOUND_DIR" ]; then
        cd "$FOUND_DIR"
        echo "✓ 找到项目目录: $FOUND_DIR"
    else
        echo "错误: 无法找到项目目录，请检查路径"
        echo "请确认项目目录位置:"
        echo "  ls -la /scratch/user/yafeili/ | grep CSCE"
        exit 1
    fi
fi

echo ""
echo "Working directory: $(pwd)"
echo ""

# ==================== 检查输入文件 =====================
echo "Checking input file..."
INPUT_ARCHIVE="${1:-to_be_evaded_ds.zip}"

# 尝试多个可能的位置
if [ -f "$INPUT_ARCHIVE" ]; then
    echo "✓ 找到输入文件: $INPUT_ARCHIVE"
elif [ -f "attacker/$INPUT_ARCHIVE" ]; then
    INPUT_ARCHIVE="attacker/$INPUT_ARCHIVE"
    echo "✓ 找到输入文件: $INPUT_ARCHIVE"
elif [ -f "/scratch/user/yafeili/704/dataset/$INPUT_ARCHIVE" ]; then
    INPUT_ARCHIVE="/scratch/user/yafeili/704/dataset/$INPUT_ARCHIVE"
    echo "✓ 找到输入文件: $INPUT_ARCHIVE"
else
    echo "错误: 输入文件不存在: $INPUT_ARCHIVE"
    echo "请将 to_be_evaded_ds.zip 放在以下位置之一:"
    echo "  - $(pwd)/$INPUT_ARCHIVE"
    echo "  - $(pwd)/attacker/$INPUT_ARCHIVE"
    echo "  - /scratch/user/yafeili/704/dataset/$INPUT_ARCHIVE"
    echo ""
    echo "或者使用参数指定:"
    echo "  sbatch attacker/slurm_attack.sh /path/to/to_be_evaded_ds.zip"
    exit 1
fi

# 创建输出目录
OUTPUT_BASE="/scratch/user/yafeili/704/attackOutput"
mkdir -p "$OUTPUT_BASE"
echo "✓ 输出目录: $OUTPUT_BASE"
echo ""

# ==================== 检查MinGW编译器（Method A需要，可选）====================
echo "Checking MinGW compiler (optional, for Method A)..."
if command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "✓ MinGW编译器已安装"
    MINGW_AVAILABLE=1
else
    echo "⚠ MinGW编译器未找到（Method A将使用fallback模式）"
    echo "  如果需要完整功能，可以安装:"
    echo "    module load GCC/12.2.0"
    echo "    # 或使用系统包管理器安装 gcc-mingw-w64-x86-64"
    MINGW_AVAILABLE=0
fi
echo ""

# ==================== 运行攻击方法 =====================
echo "=========================================="
echo "Starting attack methods..."
echo "=========================================="
echo ""

cd attacker/

# 运行所有5种方法
bash run_5_new_methods.sh "$INPUT_ARCHIVE"

ATTACK_EXIT_CODE=$?

echo ""
echo "=========================================="
echo "Attack methods completed!"
echo "Exit code: $ATTACK_EXIT_CODE"
echo "End time: $(date)"
echo "=========================================="

# 显示输出目录内容
echo ""
echo "Output directory contents:"
if [ -d "attack_results_5methods" ]; then
    ls -lht attack_results_5methods/ | head -20
    echo ""
    echo "输出文件位置:"
    echo "  $(pwd)/attack_results_5methods/"
    echo ""
    echo "生成的ZIP文件:"
    for zip_file in attack_results_5methods/*_outputs.zip; do
        if [ -f "$zip_file" ]; then
            size=$(du -h "$zip_file" | cut -f1)
            echo "  - $(basename $zip_file) ($size)"
        fi
    done
else
    echo "警告: 输出目录不存在"
fi

# 复制结果到统一输出目录（可选）
if [ -d "attack_results_5methods" ]; then
    echo ""
    echo "复制结果到统一输出目录..."
    cp -r attack_results_5methods/* "$OUTPUT_BASE/" 2>/dev/null || true
    echo "✓ 结果已复制到: $OUTPUT_BASE/"
fi

exit $ATTACK_EXIT_CODE

