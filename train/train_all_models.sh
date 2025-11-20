#!/bin/bash
# 一键训练所有5个防御模型的脚本
# 使用GPU训练，实时输出到nohup日志

set -e  # 遇到错误立即退出

# ==================== 配置区域 ====================
# 数据集路径（请根据实际情况修改）
EMBER_TRAIN_DIR="/path/to/ember2018"  # EMBER训练数据目录
EMBER_TEST_DIR="/path/to/ember2018"   # EMBER测试数据目录
CHALLENGE_DIR="/path/to/challenge"    # Challenge测试数据集目录

# 训练参数
ITERATIONS=5          # 每个模型的迭代次数
SAMPLE_RATIO=1.0      # 采样比例（1.0表示使用全部数据）
MAX_SAMPLES=""        # 每个文件最大样本数（空表示不限制）

# 输出目录
OUTPUT_DIR="trained_models_$(date +%Y%m%d_%H%M%S)"

# GPU设置
USE_GPU=true          # 是否使用GPU

# 日志文件
LOG_FILE="nohup_train_$(date +%Y%m%d_%H%M%S).out"
# ================================================

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  5个防御模型训练脚本${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# 检查参数
if [ ! -d "$EMBER_TRAIN_DIR" ]; then
    echo -e "${RED}错误: 训练数据目录不存在: $EMBER_TRAIN_DIR${NC}"
    echo "请修改脚本中的 EMBER_TRAIN_DIR 变量"
    exit 1
fi

if [ ! -d "$EMBER_TEST_DIR" ]; then
    echo -e "${RED}错误: 测试数据目录不存在: $EMBER_TEST_DIR${NC}"
    echo "请修改脚本中的 EMBER_TEST_DIR 变量"
    exit 1
fi

if [ ! -d "$CHALLENGE_DIR" ]; then
    echo -e "${YELLOW}警告: Challenge目录不存在: $CHALLENGE_DIR${NC}"
    echo "请修改脚本中的 CHALLENGE_DIR 变量"
    read -p "是否继续? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 检查GPU
if [ "$USE_GPU" = true ]; then
    if command -v nvidia-smi &> /dev/null; then
        echo -e "${GREEN}检测到NVIDIA GPU:${NC}"
        nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
    else
        echo -e "${YELLOW}警告: 未检测到NVIDIA GPU，将使用CPU训练${NC}"
    fi
fi

# 创建输出目录
mkdir -p "$OUTPUT_DIR"
echo "输出目录: $OUTPUT_DIR"

# 构建训练命令
TRAIN_CMD="python3 train/train_all_models.py"
TRAIN_CMD="$TRAIN_CMD --train-dir \"$EMBER_TRAIN_DIR\""
TRAIN_CMD="$TRAIN_CMD --test-dir \"$EMBER_TEST_DIR\""
TRAIN_CMD="$TRAIN_CMD --challenge-dir \"$CHALLENGE_DIR\""
TRAIN_CMD="$TRAIN_CMD --output-dir \"$OUTPUT_DIR\""
TRAIN_CMD="$TRAIN_CMD --iterations $ITERATIONS"
TRAIN_CMD="$TRAIN_CMD --sample-ratio $SAMPLE_RATIO"

if [ -n "$MAX_SAMPLES" ]; then
    TRAIN_CMD="$TRAIN_CMD --max-samples $MAX_SAMPLES"
fi

if [ "$USE_GPU" = true ]; then
    TRAIN_CMD="$TRAIN_CMD --use-gpu"
else
    TRAIN_CMD="$TRAIN_CMD --no-gpu"
fi

# 显示配置信息
echo ""
echo -e "${GREEN}训练配置:${NC}"
echo "  训练数据: $EMBER_TRAIN_DIR"
echo "  测试数据: $EMBER_TEST_DIR"
echo "  Challenge数据: $CHALLENGE_DIR"
echo "  输出目录: $OUTPUT_DIR"
echo "  迭代次数: $ITERATIONS"
echo "  采样比例: $SAMPLE_RATIO"
echo "  使用GPU: $USE_GPU"
echo "  日志文件: $LOG_FILE"
echo ""

# 询问确认
read -p "确认开始训练? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 0
fi

# 开始训练（使用nohup在后台运行，输出到日志文件）
echo ""
echo -e "${GREEN}开始训练...${NC}"
echo "日志将实时输出到: $LOG_FILE"
echo "可以使用以下命令查看实时日志:"
echo "  tail -f $LOG_FILE"
echo ""

# 执行训练命令，同时输出到终端和日志文件
eval $TRAIN_CMD 2>&1 | tee "$LOG_FILE"

# 检查训练结果
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}训练完成！${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "输出目录: $OUTPUT_DIR"
    echo "最佳模型: $OUTPUT_DIR/best_model.pickle"
    echo "模型比较结果: $OUTPUT_DIR/model_comparison.json"
    echo ""
    echo "各模型结果:"
    for model_dir in "$OUTPUT_DIR"/model*/; do
        if [ -d "$model_dir" ]; then
            model_name=$(basename "$model_dir")
            echo "  $model_name:"
            if [ -f "$model_dir/${model_name}_challenge_results.json" ]; then
                echo "    测试结果: $model_dir/${model_name}_challenge_results.json"
            fi
        fi
    done
else
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}训练失败！${NC}"
    echo -e "${RED}========================================${NC}"
    echo "请查看日志文件: $LOG_FILE"
    exit 1
fi

