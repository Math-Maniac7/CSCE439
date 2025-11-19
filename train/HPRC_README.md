# HPRC超算训练指南

## 概述

代码已优化为充分利用HPRC超算的GPU和内存资源，支持大规模数据集训练。

## 主要特性

1. **GPU加速**：使用LightGBM的CUDA支持，训练速度提升5-10倍
2. **无内存限制**：充分利用超算的256GB+内存
3. **大规模训练**：支持完整数据集训练（不采样）
4. **自动资源检测**：自动检测GPU可用性，fallback到CPU

## 快速开始

### 方法1: 使用SLURM脚本（推荐）

```bash
# 编辑 train/hprc_train.sh，修改数据路径
# 然后提交作业
sbatch train/hprc_train.sh
```

### 方法2: 直接运行

```bash
python3 train/train_ember_jsonl.py \
    --train-dir /path/to/ember2018 \
    --test-dir /path/to/ember2018 \
    --output defender/defender/models/ember_jsonl_model.pickle \
    --use-gpu \
    --n-estimators 1000 \
    --no-memory-limit \
    --sample-ratio 1.0
```

## 参数说明

### GPU相关
- `--use-gpu`: 启用GPU加速（默认启用）
- `--n-estimators`: 树的数量（GPU模式下建议500-1000，默认500）

### 内存相关
- `--no-memory-limit`: 不限制内存使用（超算模式推荐）
- `--sample-ratio 1.0`: 使用全部数据（默认1.0）
- `--batch-size`: 分批加载时的批次大小（默认500000）

### 数据相关
- `--train-dir`: 训练数据目录
- `--test-dir`: 测试数据目录
- `--max-samples`: 每个文件最大样本数（不推荐，会限制数据量）

## SLURM资源配置

`train/hprc_train.sh` 中的资源配置：

```bash
#SBATCH --mem=256G          # 内存：256GB
#SBATCH --cpus-per-task=32  # CPU核心：32
#SBATCH --gres=gpu:1        # GPU：1块
#SBATCH --time=24:00:00     # 时间限制：24小时
```

根据实际需求调整这些参数。

## 环境设置

### 1. 加载模块

```bash
module load Python/3.9.6-GCCcore-11.2.0
module load CUDA/11.7.0
```

### 2. 安装依赖

```bash
pip install --user lightgbm numpy pandas scikit-learn tqdm
pip install --user git+https://github.com/endgameinc/ember.git
```

### 3. 设置CUDA（如果使用GPU）

```bash
export CUDA_VISIBLE_DEVICES=0  # 使用第一块GPU
```

## 性能优化建议

1. **使用GPU**：确保 `--use-gpu` 启用，速度提升显著
2. **增加树数量**：GPU模式下可以使用更多树（1000+）
3. **全数据训练**：使用 `--sample-ratio 1.0` 和 `--no-memory-limit`
4. **监控资源**：使用 `squeue` 和 `sstat` 监控作业

## 输出说明

训练完成后会输出：
- 模型文件：`defender/defender/models/ember_jsonl_model.pickle`
- 性能指标：FPR, TPR, Accuracy等
- 训练日志：包含详细训练过程

## 故障排除

### GPU不可用
- 检查CUDA模块是否加载
- 检查 `CUDA_VISIBLE_DEVICES` 设置
- 代码会自动fallback到CPU模式

### 内存不足
- 使用 `--no-memory-limit` 充分利用超算内存
- 如果仍不足，可以适当使用 `--sample-ratio`

### 训练时间过长
- 启用GPU加速（`--use-gpu`）
- 减少树的数量（`--n-estimators`）
- 使用采样（`--sample-ratio 0.5`）

## 示例

### 完整数据集训练（推荐）

```bash
python3 train/train_ember_jsonl.py \
    --train-dir /scratch/user/ember2018 \
    --test-dir /scratch/user/ember2018 \
    --output models/ember_full.pickle \
    --use-gpu \
    --n-estimators 1000 \
    --no-memory-limit \
    --sample-ratio 1.0
```

### 快速测试

```bash
python3 train/train_ember_jsonl.py \
    --train-dir /scratch/user/ember2018 \
    --test-dir /scratch/user/ember2018 \
    --output models/ember_test.pickle \
    --use-gpu \
    --max-samples 100000
```

## 注意事项

1. 确保数据路径正确
2. 检查GPU可用性：`nvidia-smi`
3. 监控内存使用：避免OOM
4. 保存训练日志以便分析

