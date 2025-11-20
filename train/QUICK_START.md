# 快速开始指南

## 一键训练所有5个防御模型

### 步骤1: 配置数据集路径

编辑 `train/train_all_models.sh`，修改以下变量：

```bash
EMBER_TRAIN_DIR="/path/to/ember2018"  # 例如: /Users/felix/Documents/704/dataset/ember2018
EMBER_TEST_DIR="/path/to/ember2018"   # 同上
CHALLENGE_DIR="/path/to/challenge"    # Challenge测试数据集目录
```

### 步骤2: 运行训练脚本

```bash
cd /Users/felix/Documents/704/code/CSCE439
bash train/train_all_models.sh
```

### 步骤3: 查看训练进度

在另一个终端窗口查看实时日志：

```bash
tail -f nohup_train_*.out
```

### 步骤4: 查看结果

训练完成后，查看最佳模型：

```bash
# 查看模型比较结果
cat trained_models_*/model_comparison.json | python3 -m json.tool

# 查看最佳模型路径
ls -lh trained_models_*/best_model.pickle
```

## 预期输出

训练过程会：

1. **训练5个不同的模型**（每个模型迭代5次）
2. **在challenge数据集上测试每个模型**
3. **自动选择最佳模型**（基于TPR、FPR、准确率）
4. **保存所有结果**到输出目录

## 训练时间估算

- **单个模型单次迭代**: 约30-60分钟（取决于数据量和硬件）
- **5个模型 × 5次迭代**: 约12-25小时（使用GPU）
- **CPU训练**: 时间会显著增加（可能2-3倍）

## 输出文件说明

- `best_model.pickle`: 最佳模型（可直接用于部署）
- `model_comparison.json`: 所有模型的性能比较
- `model*/model*_best.pickle`: 每个模型的最佳版本
- `model*/model*_challenge_results.json`: 每个模型的challenge测试结果
- `model*/model*_training_results.json`: 每个模型的训练历史

## 常见问题

### Q: 如何只训练特定模型？

A: 修改脚本中的模型列表，或直接运行：

```bash
python3 train/train_all_models.py \
    --train-dir /path/to/ember2018 \
    --test-dir /path/to/ember2018 \
    --challenge-dir /path/to/challenge \
    --models model1 model2 \
    --use-gpu
```

### Q: 如何减少训练时间？

A: 使用采样或限制样本数：

```bash
# 在脚本中修改
SAMPLE_RATIO=0.5      # 只使用50%的数据
MAX_SAMPLES=100000    # 每个文件最多10万样本
ITERATIONS=3          # 减少迭代次数
```

### Q: 如何查看GPU使用情况？

A: 在另一个终端运行：

```bash
watch -n 1 nvidia-smi
```

### Q: 训练中断了怎么办？

A: 脚本支持断点续传，但需要手动指定已训练的模型。或者重新运行，已存在的模型会被跳过（需要修改脚本）。

## 下一步

训练完成后：

1. **部署最佳模型**: 将 `best_model.pickle` 复制到 `defender/defender/models/`
2. **测试模型**: 使用Docker部署并测试
3. **优化**: 根据测试结果调整参数重新训练

