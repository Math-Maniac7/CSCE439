# 内存优化指南

## 问题说明

默认情况下，训练脚本会一次性将所有数据加载到内存中。对于几十GB的EMBER数据集，这可能导致内存不足。

## 解决方案

### 方案1: 使用采样（推荐，最简单）

只使用数据集的一部分进行训练：

```bash
# 使用10%的数据训练
python train/train_ember_jsonl.py \
    --train-dir /path/to/data \
    --output model.pickle \
    --sample-ratio 0.1

# 使用20%的数据训练
python train/train_ember_jsonl.py \
    --train-dir /path/to/data \
    --output model.pickle \
    --sample-ratio 0.2
```

**优点**：
- 简单易用
- 内存占用小
- 训练速度快

**缺点**：
- 可能影响模型性能（但通常10-20%的数据已经足够）

### 方案2: 限制每个文件的样本数

```bash
# 每个文件最多加载10万样本
python train/train_ember_jsonl.py \
    --train-dir /path/to/data \
    --output model.pickle \
    --max-samples 100000
```

**优点**：
- 可以控制总数据量
- 内存使用可预测

**缺点**：
- 可能浪费部分数据

### 方案3: 使用分批加载模式（实验性）

```bash
# 使用分批加载（批次大小50,000）
python train/train_ember_jsonl.py \
    --train-dir /path/to/data \
    --output model.pickle \
    --use-batch \
    --batch-size 50000
```

**注意**：此模式仍在优化中，RandomForest不支持真正的增量训练，所以会分批累积数据后重新训练。

## 内存估算

每个样本的特征向量：
- 2381维 × 4字节（float32） = 9.5 KB/样本

内存使用估算：
- 10万样本 ≈ 950 MB
- 50万样本 ≈ 4.75 GB
- 100万样本 ≈ 9.5 GB
- 500万样本 ≈ 47.5 GB

## 推荐配置

### 8GB内存
```bash
--max-samples 50000  # 或
--sample-ratio 0.05  # 5%的数据
```

### 16GB内存
```bash
--max-samples 100000  # 或
--sample-ratio 0.1   # 10%的数据
```

### 32GB内存
```bash
--max-samples 200000  # 或
--sample-ratio 0.2    # 20%的数据
```

### 64GB+内存
```bash
# 可以使用更多数据，或移除限制
--sample-ratio 0.5    # 50%的数据
```

## 性能建议

1. **先小规模测试**：使用 `--max-samples 1000` 或 `--sample-ratio 0.01` 快速测试
2. **逐步增加**：确认代码正常后，逐步增加数据量
3. **监控内存**：使用 `htop` 或 `top` 监控内存使用
4. **使用SSD**：如果内存不足，确保使用SSD以提高I/O速度

## 示例

```bash
# 快速测试（1%数据，约1-2分钟）
python train/train_ember_jsonl.py \
    --train-dir /Users/felix/Documents/704/dataset/ember2018 \
    --output model_test.pickle \
    --sample-ratio 0.01

# 中等规模（10%数据，约10-20分钟）
python train/train_ember_jsonl.py \
    --train-dir /Users/felix/Documents/704/dataset/ember2018 \
    --output model_10pct.pickle \
    --sample-ratio 0.1

# 大规模（如果内存足够）
python train/train_ember_jsonl.py \
    --train-dir /Users/felix/Documents/704/dataset/ember2018 \
    --output model_full.pickle \
    --max-samples 500000
```

