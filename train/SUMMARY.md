# 5个防御模型训练系统 - 总结

## 📋 系统概述

已创建完整的5个防御模型训练和测试系统，包括：

1. **5个不同的防御模型**（不同算法和参数配置）
2. **迭代训练机制**（多次训练并自动选择最佳模型）
3. **Challenge测试系统**（在challenge数据集上测试并验证100%准确率要求）
4. **自动化训练脚本**（一键训练所有模型）
5. **GPU加速支持**（自动检测并使用GPU）

## 📁 文件清单

### 核心文件

1. **`model_definitions.py`** - 5个模型定义
   - Model1: LightGBM深度模型（1500树，深度35）
   - Model2: LightGBM宽模型（1200树，127叶子节点）
   - Model3: XGBoost模型（1000树，深度30）
   - Model4: RandomForest集成模型（2000树，深度40）
   - Model5: LightGBM快速模型（800树，深度20）

2. **`train_iterative.py`** - 迭代训练脚本
   - 支持多次迭代训练单个模型
   - 自动保存最佳模型
   - 记录所有迭代的训练结果

3. **`test_challenge.py`** - Challenge测试脚本
   - 测试模型在goodware和malware上的表现
   - 计算FPR、TPR、准确率等指标
   - 验证是否达到100%准确率要求

4. **`train_all_models.py`** - 主训练脚本
   - 训练所有5个模型
   - 自动测试每个模型
   - 比较并选择最佳模型

5. **`train_all_models.sh`** - 一键运行脚本
   - 配置数据集路径
   - 使用GPU训练
   - 实时输出到nohup日志

### 文档文件

- `README_TRAINING.md` - 详细使用文档
- `QUICK_START.md` - 快速开始指南
- `SUMMARY.md` - 本文档

## 🚀 快速开始

### 1. 配置数据集路径

编辑 `train/train_all_models.sh`：

```bash
EMBER_TRAIN_DIR="/path/to/ember2018"
EMBER_TEST_DIR="/path/to/ember2018"
CHALLENGE_DIR="/path/to/challenge"
```

### 2. 运行训练

```bash
cd /Users/felix/Documents/704/code/CSCE439
bash train/train_all_models.sh
```

### 3. 查看日志

```bash
tail -f nohup_train_*.out
```

## 📊 工作流程

```
1. 训练阶段
   ├── 对每个模型（model1-5）
   │   ├── 迭代训练（默认5次）
   │   ├── 评估每次迭代的性能
   │   └── 保存最佳模型
   │
2. 测试阶段
   ├── 对每个模型
   │   ├── 在challenge数据集上测试
   │   ├── 计算goodware和malware准确率
   │   └── 验证100%准确率要求
   │
3. 选择阶段
   ├── 比较所有模型的性能
   ├── 计算综合得分（TPR、FPR、准确率）
   └── 选择并保存最佳模型
```

## 🎯 模型选择标准

系统根据以下标准选择最佳模型：

- **TPR (真阳性率)**: 权重 40%，目标 ≥ 95%
- **FPR (假阳性率)**: 权重 30%，目标 ≤ 1%
- **准确率**: 权重 20%
- **100%准确率奖励**: 权重 10%（goodware或malware至少一个达到100%）

**综合得分公式**:
```
Score = TPR × 0.4 + (1-FPR) × 0.3 + Accuracy × 0.2 + 100%奖励 × 0.1
```

## 📈 输出结构

```
trained_models_YYYYMMDD_HHMMSS/
├── best_model.pickle              # 最佳模型（自动选择）
├── model_comparison.json          # 模型比较结果
├── model1/
│   ├── model1_best.pickle
│   ├── model1_training_results.json
│   └── model1_challenge_results.json
├── model2/
│   └── ...
├── model3/
│   └── ...
├── model4/
│   └── ...
└── model5/
    └── ...
```

## ✅ 挑战要求检查

系统自动检查以下要求：

- ✅ **FPR ≤ 1%**: 假阳性率不超过1%
- ✅ **TPR ≥ 95%**: 真阳性率至少95%
- ✅ **至少一个set达到100%**: goodware或malware至少有一个set达到100%准确率

## 🔧 配置选项

### 训练参数

- `--iterations`: 每个模型的迭代次数（默认5）
- `--sample-ratio`: 采样比例（默认1.0，使用全部数据）
- `--max-samples`: 每个文件最大样本数（默认无限制）
- `--use-gpu`: 使用GPU训练（默认启用）
- `--no-gpu`: 禁用GPU

### 数据集路径

- `--train-dir`: EMBER训练数据目录
- `--test-dir`: EMBER测试数据目录
- `--challenge-dir`: Challenge测试数据集目录

## 💡 使用技巧

### 1. 快速测试

使用小数据集快速测试：

```bash
python3 train/train_all_models.py \
    --train-dir /path/to/ember2018 \
    --test-dir /path/to/ember2018 \
    --challenge-dir /path/to/challenge \
    --sample-ratio 0.1 \
    --max-samples 10000 \
    --iterations 2
```

### 2. 只训练特定模型

```bash
python3 train/train_all_models.py \
    ... \
    --models model1 model2
```

### 3. 查看GPU使用情况

```bash
watch -n 1 nvidia-smi
```

### 4. 后台运行

```bash
nohup bash train/train_all_models.sh > training.log 2>&1 &
```

## ⚠️ 注意事项

1. **内存要求**: 建议至少16GB RAM（完整数据集）
2. **训练时间**: 5个模型×5次迭代可能需要12-25小时（GPU）
3. **磁盘空间**: 每个模型约500MB-1GB
4. **GPU要求**: 可选，但强烈推荐（速度提升5-10倍）

## 🐛 故障排除

### 导入错误

确保在项目根目录运行：

```bash
cd /Users/felix/Documents/704/code/CSCE439
```

### GPU不可用

使用 `--no-gpu` 参数，或检查CUDA安装：

```bash
nvidia-smi
```

### 内存不足

减少数据量：

```bash
--sample-ratio 0.5 --max-samples 100000
```

### Challenge目录找不到

确保目录结构：

```
challenge/
├── goodware/  (或 benign/)
└── malware/   (或 malicious/)
```

或提供ZIP文件。

## 📚 相关文档

- `README_TRAINING.md` - 详细使用文档
- `QUICK_START.md` - 快速开始指南
- `train_ember_jsonl.py` - 基础训练脚本（参考）
- `EMBER_MODEL_GUIDE.md` - EMBER模型指南

## 🎓 下一步

训练完成后：

1. **部署最佳模型**: 复制 `best_model.pickle` 到 `defender/defender/models/`
2. **Docker测试**: 构建并测试Docker镜像
3. **性能优化**: 根据测试结果调整参数重新训练

## 📞 支持

如有问题，请查看：
- `README_TRAINING.md` - 详细文档
- `QUICK_START.md` - 快速开始
- 代码注释 - 每个文件都有详细注释

