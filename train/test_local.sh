#!/bin/bash
# 本地测试脚本 - 快速验证代码功能
# 使用小数据集和少量迭代

set -e

echo "=========================================="
echo "本地测试脚本 - 快速验证"
echo "=========================================="
echo ""

# ==================== 配置区域 ====================
# 数据集路径（请根据本地实际情况修改）
DATASET_BASE="/Users/felix/Documents/704/dataset"  # 本地数据集路径

# 三个EMBER数据集目录（至少需要一个）
EMBER_DATASET_2017_2="$DATASET_BASE/ember_2017_2"
EMBER_DATASET_2018_2="$DATASET_BASE/ember2018"
EMBER_DATASET="$DATASET_BASE/ember"

# Challenge验证集目录
CHALLENGE_DIR="$DATASET_BASE/challenge_ds"

# 训练参数（测试模式：快速）
ITERATIONS=2          # 测试时只用2次迭代
SAMPLE_RATIO=0.01     # 只用1%的数据快速测试
MAX_SAMPLES=1000      # 每个文件最多1000个样本

# 输出目录
OUTPUT_DIR="test_output_$(date +%Y%m%d_%H%M%S)"

# GPU设置
USE_GPU=false         # 本地测试通常不用GPU
# ================================================

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}测试配置:${NC}"
echo "  数据集基础目录: $DATASET_BASE"
echo "  输出目录: $OUTPUT_DIR"
echo "  迭代次数: $ITERATIONS (测试模式)"
echo "  采样比例: $SAMPLE_RATIO (1%数据)"
echo "  最大样本数: $MAX_SAMPLES"
echo "  使用GPU: $USE_GPU"
echo ""

# 检查数据集目录
FOUND_DATASETS=0
if [ -d "$EMBER_DATASET_2017_2" ]; then
    echo "✓ 找到: $EMBER_DATASET_2017_2"
    FOUND_DATASETS=$((FOUND_DATASETS + 1))
fi
if [ -d "$EMBER_DATASET_2018_2" ]; then
    echo "✓ 找到: $EMBER_DATASET_2018_2"
    FOUND_DATASETS=$((FOUND_DATASETS + 1))
fi
if [ -d "$EMBER_DATASET" ]; then
    echo "✓ 找到: $EMBER_DATASET"
    FOUND_DATASETS=$((FOUND_DATASETS + 1))
fi

if [ $FOUND_DATASETS -eq 0 ]; then
    echo -e "${RED}错误: 未找到任何数据集目录${NC}"
    echo "请修改脚本中的DATASET_BASE路径，或确保数据集已解压"
    exit 1
fi

if [ ! -d "$CHALLENGE_DIR" ]; then
    echo -e "${YELLOW}警告: Challenge目录不存在: $CHALLENGE_DIR${NC}"
    echo "将跳过challenge验证"
    CHALLENGE_DIR=""  # 设为空，跳过challenge测试
fi

# 检查Python环境
echo ""
echo "检查Python环境..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}错误: 未找到python3${NC}"
    exit 1
fi

python3 --version

# 检查必要的包
echo ""
echo "检查Python包..."
python3 -c "import numpy" 2>/dev/null && echo "✓ numpy" || echo "✗ numpy (未安装)"
python3 -c "import pandas" 2>/dev/null && echo "✓ pandas" || echo "✗ pandas (未安装)"
python3 -c "import sklearn" 2>/dev/null && echo "✓ scikit-learn" || echo "✗ scikit-learn (未安装)"
python3 -c "import lightgbm" 2>/dev/null && echo "✓ lightgbm" || echo "✗ lightgbm (未安装)"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

# 构建训练命令
TRAIN_CMD="python3 train/train_all_models.py"

# 添加数据集目录
if [ -d "$EMBER_DATASET_2017_2" ]; then
    TRAIN_CMD="$TRAIN_CMD --dataset-dir \"$EMBER_DATASET_2017_2\""
fi
if [ -d "$EMBER_DATASET_2018_2" ]; then
    TRAIN_CMD="$TRAIN_CMD --dataset-dir \"$EMBER_DATASET_2018_2\""
fi
if [ -d "$EMBER_DATASET" ]; then
    TRAIN_CMD="$TRAIN_CMD --dataset-dir \"$EMBER_DATASET\""
fi

# 如果有challenge目录，添加challenge参数
if [ -n "$CHALLENGE_DIR" ] && [ -d "$CHALLENGE_DIR" ]; then
    TRAIN_CMD="$TRAIN_CMD --challenge-dir \"$CHALLENGE_DIR\""
fi

TRAIN_CMD="$TRAIN_CMD --output-dir \"$OUTPUT_DIR\""
TRAIN_CMD="$TRAIN_CMD --iterations $ITERATIONS"
TRAIN_CMD="$TRAIN_CMD --sample-ratio $SAMPLE_RATIO"
TRAIN_CMD="$TRAIN_CMD --max-samples $MAX_SAMPLES"

if [ "$USE_GPU" = false ]; then
    TRAIN_CMD="$TRAIN_CMD --no-gpu"
fi

# 只测试第一个模型（最快）
TRAIN_CMD="$TRAIN_CMD --models model1"

echo ""
echo -e "${GREEN}开始测试...${NC}"
echo "执行命令: $TRAIN_CMD"
echo ""

# 执行训练
eval $TRAIN_CMD

# 检查结果
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}测试完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "输出目录: $OUTPUT_DIR"
    echo ""
    echo "检查输出文件:"
    ls -lh "$OUTPUT_DIR"/*/ 2>/dev/null | head -10 || echo "  输出目录为空"
else
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}测试失败！${NC}"
    echo -e "${RED}========================================${NC}"
    exit 1
fi

