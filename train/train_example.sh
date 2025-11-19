#!/bin/bash
# EMBER模型训练示例脚本

# 设置数据集路径
EMBER2018_DIR="/Users/felix/Documents/704/dataset/ember2018"
EMBER_2017_2_DIR="/Users/felix/Documents/704/dataset/ember_2017_2"
EMBER_DATASET_DIR="/Users/felix/Documents/704/dataset/ember_dataset/ember"

# 输出模型路径
MODEL_OUTPUT="defender/defender/models/ember_jsonl_model.pickle"

# 进入项目根目录
cd "$(dirname "$0")/.."

echo "=== EMBER模型训练示例 ==="
echo ""
echo "选择训练数据集:"
echo "1) ember2018"
echo "2) ember_2017_2"
echo "3) ember_dataset"
echo "4) 快速测试 (使用少量数据)"
echo ""
read -p "请输入选项 (1-4): " choice

case $choice in
    1)
        TRAIN_DIR=$EMBER2018_DIR
        TEST_DIR=$EMBER2018_DIR
        MAX_SAMPLES=""
        ;;
    2)
        TRAIN_DIR=$EMBER_2017_2_DIR
        TEST_DIR=$EMBER_2017_2_DIR
        MAX_SAMPLES=""
        ;;
    3)
        TRAIN_DIR=$EMBER_DATASET_DIR
        TEST_DIR=$EMBER_DATASET_DIR
        MAX_SAMPLES=""
        ;;
    4)
        TRAIN_DIR=$EMBER2018_DIR
        TEST_DIR=$EMBER2018_DIR
        MAX_SAMPLES="--max-samples 10000"
        echo "使用快速测试模式（10,000样本）"
        ;;
    *)
        echo "无效选项，使用默认: ember2018"
        TRAIN_DIR=$EMBER2018_DIR
        TEST_DIR=$EMBER2018_DIR
        MAX_SAMPLES=""
        ;;
esac

echo ""
echo "训练配置:"
echo "  训练目录: $TRAIN_DIR"
echo "  测试目录: $TEST_DIR"
echo "  模型输出: $MODEL_OUTPUT"
echo ""

# 检查训练目录是否存在
if [ ! -d "$TRAIN_DIR" ]; then
    echo "错误: 训练目录不存在: $TRAIN_DIR"
    exit 1
fi

# 运行训练
echo "开始训练..."
python train/train_ember_jsonl.py \
    --train-dir "$TRAIN_DIR" \
    --test-dir "$TEST_DIR" \
    --output "$MODEL_OUTPUT" \
    $MAX_SAMPLES

if [ $? -eq 0 ]; then
    echo ""
    echo "=== 训练完成 ==="
    echo "模型已保存到: $MODEL_OUTPUT"
    echo ""
    echo "下一步: 部署模型到Docker"
    echo "  1. 确保模型文件在正确位置"
    echo "  2. 构建Docker镜像: cd defender && docker build -t malware-defense-ember ."
    echo "  3. 运行容器: docker run --memory=1g -p 8080:8080 -e DF_MODEL_NAME=ember_jsonl malware-defense-ember"
else
    echo ""
    echo "=== 训练失败 ==="
    exit 1
fi

