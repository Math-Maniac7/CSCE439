# 5个防御模型训练指南

本目录包含训练5个不同防御模型的完整系统。

## 文件说明

- `model_definitions.py`: 定义5个不同的防御模型
  - Model1: LightGBM深度模型（更多树，更深深度）
  - Model2: LightGBM宽模型（更多叶子节点）
  - Model3: XGBoost模型（不同的boosting算法）
  - Model4: RandomForest集成模型（经典但有效）
  - Model5: LightGBM快速模型（平衡速度和性能）

- `train_iterative.py`: 迭代训练单个模型
  - 支持多次迭代训练
  - 自动保存最佳模型
  - 记录所有迭代的训练结果

- `test_challenge.py`: Challenge数据集测试
  - 测试模型在goodware和malware上的表现
  - 计算FPR、TPR、准确率等指标
  - 检查是否达到100%准确率要求

- `train_all_models.py`: 主训练脚本
  - 训练所有5个模型
  - 自动测试每个模型
  - 比较并选择最佳模型

- `train_all_models.sh`: 一键运行脚本
  - 配置数据集路径
  - 使用GPU训练
  - 实时输出到nohup日志

## 使用方法

### 方法1: 使用一键脚本（推荐）

1. 编辑 `train_all_models.sh`，修改以下配置：
   ```bash
   EMBER_TRAIN_DIR="/path/to/ember2018"  # EMBER训练数据目录
   EMBER_TEST_DIR="/path/to/ember2018"   # EMBER测试数据目录
   CHALLENGE_DIR="/path/to/challenge"     # Challenge测试数据集目录
   ITERATIONS=5                           # 每个模型的迭代次数
   SAMPLE_RATIO=1.0                      # 采样比例
   ```

2. 运行脚本：
   ```bash
   bash train/train_all_models.sh
   ```

3. 查看实时日志：
   ```bash
   tail -f nohup_train_*.out
   ```

### 方法2: 手动运行

#### 训练单个模型

```bash
python3 train/train_iterative.py \
    --model-id model1 \
    --train-dir /path/to/ember2018 \
    --test-dir /path/to/ember2018 \
    --output-dir models/model1 \
    --iterations 5 \
    --use-gpu \
    --sample-ratio 1.0
```

#### 测试模型

```bash
python3 train/test_challenge.py \
    --model-path models/model1/model1_best.pickle \
    --challenge-dir /path/to/challenge \
    --output models/model1/model1_challenge_results.json
```

#### 训练所有模型

```bash
python3 train/train_all_models.py \
    --train-dir /path/to/ember2018 \
    --test-dir /path/to/ember2018 \
    --challenge-dir /path/to/challenge \
    --output-dir trained_models \
    --iterations 5 \
    --use-gpu \
    --sample-ratio 1.0
```

## 输出结构

训练完成后，输出目录结构如下：

```
trained_models/
├── best_model.pickle                    # 最佳模型（自动选择）
├── model_comparison.json                # 模型比较结果
├── model1/
│   ├── model1_best.pickle              # 模型1的最佳版本
│   ├── model1_training_results.json    # 训练结果
│   └── model1_challenge_results.json   # Challenge测试结果
├── model2/
│   └── ...
├── model3/
│   └── ...
├── model4/
│   └── ...
└── model5/
    └── ...
```

## 模型选择标准

系统会根据以下标准选择最佳模型：

1. **TPR (真阳性率)**: 权重 40%，目标 ≥ 95%
2. **FPR (假阳性率)**: 权重 30%，目标 ≤ 1%
3. **准确率**: 权重 20%
4. **100%准确率奖励**: 权重 10%（goodware或malware至少一个达到100%）

综合得分 = TPR × 0.4 + (1-FPR) × 0.3 + Accuracy × 0.2 + 100%奖励 × 0.1

## 要求

根据挑战要求，模型需要满足：

- **FPR ≤ 1%**: 假阳性率不超过1%
- **TPR ≥ 95%**: 真阳性率至少95%
- **至少一个set达到100%**: goodware或malware至少有一个set达到100%准确率

## GPU支持

系统自动检测GPU可用性：

- 如果安装了LightGBM/XGBoost且检测到GPU，自动使用GPU训练
- 否则回退到CPU训练（RandomForest）

## 注意事项

1. **内存使用**: 训练大数据集时可能需要大量内存（建议至少16GB）
2. **训练时间**: 完整数据集训练可能需要数小时（取决于硬件）
3. **模型大小**: 训练好的模型文件可能较大（几百MB）
4. **Docker限制**: 确保Docker镜像（未压缩）不超过1GB

## 故障排除

### 问题1: 导入错误

**解决方案**: 确保在项目根目录运行脚本

```bash
cd /path/to/CSCE439
python3 train/train_all_models.py ...
```

### 问题2: GPU不可用

**解决方案**: 检查CUDA和GPU驱动

```bash
nvidia-smi
```

如果GPU不可用，使用 `--no-gpu` 参数：

```bash
python3 train/train_all_models.py ... --no-gpu
```

### 问题3: 内存不足

**解决方案**: 使用采样或限制样本数

```bash
python3 train/train_all_models.py ... --sample-ratio 0.5 --max-samples 100000
```

### 问题4: Challenge目录找不到

**解决方案**: 确保challenge目录结构如下：

```
challenge/
├── goodware/    # 或 benign/
│   └── *.exe
└── malware/     # 或 malicious/
    └── *.exe
```

或者提供ZIP文件：

```
challenge/
├── goodware.zip
└── malware.zip
```

