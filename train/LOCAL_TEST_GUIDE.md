# 本地测试指南

## 快速测试

### 方法1: 使用测试脚本（推荐）

```bash
# 1. 编辑测试脚本，修改数据集路径
vim train/test_local.sh
# 修改 DATASET_BASE="/Users/felix/Documents/704/dataset"

# 2. 运行测试
bash train/test_local.sh
```

### 方法2: 手动测试单个模型（最快）

```bash
# 测试单个模型，使用1000个样本
python3 train/test_single_model.py \
    --model-id model1 \
    --dataset-dir /path/to/ember2018 \
    --max-samples 1000
```

### 方法3: 直接运行训练脚本（最小配置）

```bash
# 使用最小数据集和迭代次数
python3 train/train_all_models.py \
    --dataset-dir /path/to/ember2018 \
    --challenge-dir /path/to/challenge \
    --output-dir test_output \
    --iterations 1 \
    --max-samples 1000 \
    --sample-ratio 0.01 \
    --models model1 \
    --no-gpu
```

## 测试配置说明

### 快速测试参数

| 参数 | 测试值 | 说明 |
|------|--------|------|
| `--iterations` | 1-2 | 只训练1-2次 |
| `--max-samples` | 1000 | 每个文件最多1000样本 |
| `--sample-ratio` | 0.01 | 只使用1%数据 |
| `--models` | model1 | 只测试一个模型 |
| `--no-gpu` | - | 不使用GPU（本地通常没有） |

### 完整测试参数

| 参数 | 值 | 说明 |
|------|-----|------|
| `--iterations` | 5 | 完整迭代次数 |
| `--sample-ratio` | 1.0 | 使用全部数据 |
| `--models` | all | 训练所有模型 |

## 测试检查清单

- [ ] Python环境正常
- [ ] 必要的包已安装（numpy, pandas, scikit-learn, lightgbm）
- [ ] 数据集路径正确
- [ ] 代码能正常加载数据
- [ ] 模型能正常训练
- [ ] 评估功能正常
- [ ] 输出文件正常生成

## 常见问题

### 问题1: 包未安装

```bash
pip install numpy pandas scikit-learn tqdm lightgbm
```

### 问题2: ember库未安装

```bash
pip install git+https://github.com/endgameinc/ember.git
```

### 问题3: 数据路径错误

检查数据集目录结构：
```
/path/to/ember2018/
├── train_features_0.jsonl
├── train_features_1.jsonl
└── ...
```

### 问题4: 内存不足

使用更小的测试参数：
```bash
--max-samples 500
--sample-ratio 0.005
```

