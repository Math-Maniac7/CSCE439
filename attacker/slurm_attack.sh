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

# ==================== 检查输入文件或目录 =====================
echo "Checking input file or directory..."
INPUT_PATH="${1:-/scratch/user/yafeili/704/dataset/to_be_evaded_ds}"

# 尝试多个可能的位置
FOUND_INPUT=""
if [ -f "$INPUT_PATH" ]; then
    FOUND_INPUT="$INPUT_PATH"
    echo "✓ 找到输入文件: $FOUND_INPUT"
elif [ -d "$INPUT_PATH" ]; then
    FOUND_INPUT="$INPUT_PATH"
    echo "✓ 找到输入目录: $FOUND_INPUT"
elif [ -f "/scratch/user/yafeili/704/dataset/to_be_evaded_ds.zip" ]; then
    FOUND_INPUT="/scratch/user/yafeili/704/dataset/to_be_evaded_ds.zip"
    echo "✓ 找到输入文件: $FOUND_INPUT"
elif [ -d "/scratch/user/yafeili/704/dataset/to_be_evaded_ds" ]; then
    FOUND_INPUT="/scratch/user/yafeili/704/dataset/to_be_evaded_ds"
    echo "✓ 找到输入目录: $FOUND_INPUT"
elif [ -f "attacker/to_be_evaded_ds.zip" ]; then
    FOUND_INPUT="attacker/to_be_evaded_ds.zip"
    echo "✓ 找到输入文件: $FOUND_INPUT"
elif [ -d "attacker/to_be_evaded_ds" ]; then
    FOUND_INPUT="attacker/to_be_evaded_ds"
    echo "✓ 找到输入目录: $FOUND_INPUT"
else
    echo "错误: 输入文件或目录不存在"
    echo "请将 to_be_evaded_ds 放在以下位置之一:"
    echo "  - /scratch/user/yafeili/704/dataset/to_be_evaded_ds (目录，默认)"
    echo "  - /scratch/user/yafeili/704/dataset/to_be_evaded_ds.zip (zip文件)"
    echo "  - $(pwd)/attacker/to_be_evaded_ds"
    echo ""
    echo "或者使用参数指定:"
    echo "  sbatch attacker/slurm_attack.sh /path/to/to_be_evaded_ds"
    exit 1
fi

# 如果是目录，需要压缩成zip
if [ -d "$FOUND_INPUT" ]; then
    echo ""
    echo "输入是目录，正在压缩成zip文件..."
    TEMP_ZIP="$TMPDIR/to_be_evaded_ds_$$.zip"
    
    # 压缩目录（排除sha256sums.txt，因为攻击方法会生成新的）
    cd "$(dirname "$FOUND_INPUT")"
    zip -q -r "$TEMP_ZIP" "$(basename "$FOUND_INPUT")" -x "*/sha256sums.txt"
    
    if [ -f "$TEMP_ZIP" ]; then
        INPUT_ARCHIVE="$TEMP_ZIP"
        echo "✓ 已压缩: $INPUT_ARCHIVE"
        echo "  源目录: $FOUND_INPUT"
        echo "  临时zip: $INPUT_ARCHIVE"
    else
        echo "错误: 压缩目录失败"
        exit 1
    fi
    cd "$PROJECT_DIR"
elif [ -f "$FOUND_INPUT" ]; then
    INPUT_ARCHIVE="$FOUND_INPUT"
    echo "✓ 使用zip文件: $INPUT_ARCHIVE"
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

# 清理临时zip文件（如果是从目录压缩的）
if [ -n "$TEMP_ZIP" ] && [ -f "$TEMP_ZIP" ]; then
    echo ""
    echo "清理临时zip文件..."
    rm -f "$TEMP_ZIP"
    echo "✓ 已清理: $TEMP_ZIP"
fi

exit $ATTACK_EXIT_CODE

