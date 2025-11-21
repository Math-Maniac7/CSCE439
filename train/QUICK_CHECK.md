# 快速检查指南

## 本地环境检查

### 一键检查所有配置

```bash
# 运行检查脚本（会自动检查所有内容）
bash train/check_setup.sh
```

这个脚本会检查：
- ✅ Python环境
- ✅ Python包（numpy, pandas, sklearn, lightgbm, ember）
- ✅ 项目目录和关键文件
- ✅ 数据集目录和JSONL文件
- ✅ 输出目录权限
- ✅ Python代码语法
- ✅ 模块导入
- ✅ 基本功能测试

### 手动检查（逐步）

#### 1. 检查Python环境

```bash
python3 --version
which python3
```

#### 2. 检查Python包

```bash
python3 -c "import numpy; print('numpy OK')"
python3 -c "import pandas; print('pandas OK')"
python3 -c "import sklearn; print('sklearn OK')"
python3 -c "import lightgbm; print('lightgbm OK')"
python3 -c "import ember; print('ember OK')"
```

#### 3. 检查项目目录

```bash
cd /Users/felix/Documents/704/code/CSCE439
ls -la train/*.py
```

应该看到：
- `train_all_models.py`
- `train_iterative.py`
- `load_datasets.py`
- `model_definitions.py`

#### 4. 检查数据集目录

```bash
# 修改为你的实际路径
DATASET_BASE="/Users/felix/Documents/704/dataset"

# 检查目录是否存在
ls -la "$DATASET_BASE"

# 检查是否包含数据集
ls -la "$DATASET_BASE"/ember2018
ls -la "$DATASET_BASE"/ember_2017_2

# 检查JSONL文件
find "$DATASET_BASE" -name "train_features_*.jsonl" | head -5
```

#### 5. 测试代码导入

```bash
cd /Users/felix/Documents/704/code/CSCE439

# 测试导入
python3 -c "from train.model_definitions import create_model; print('✓ OK')"
python3 -c "from train.load_datasets import load_all_ember_datasets; print('✓ OK')"
```

#### 6. 测试创建模型

```bash
python3 -c "
from train.model_definitions import create_model
m = create_model('model1', use_gpu=False)
print('✓ 模型创建成功')
"
```

## 快速修复命令

### 如果包缺失

```bash
# 安装基础包
pip3 install numpy pandas scikit-learn tqdm lightgbm

# 安装EMBER库
pip3 install git+https://github.com/endgameinc/ember.git

# 安装其他依赖
pip3 install pefile lief requests
```

### 如果路径不对

编辑 `train/check_setup.sh`，修改：
```bash
DATASET_BASE="/Users/felix/Documents/704/dataset"  # 改为你的路径
PROJECT_DIR="/Users/felix/Documents/704/code/CSCE439"  # 改为你的路径
```

## 常见问题

### Q: 检查脚本报错"路径不存在"

**A:** 修改脚本开头的路径配置：
```bash
vim train/check_setup.sh
# 修改 DATASET_BASE 和 PROJECT_DIR
```

### Q: Python包未安装

**A:** 安装缺失的包：
```bash
pip3 install <package_name>
```

### Q: ember库无法导入

**A:** 从GitHub安装：
```bash
pip3 install git+https://github.com/endgameinc/ember.git
```

### Q: 找不到数据集目录

**A:** 检查数据集是否已解压：
```bash
# 检查tar文件
ls -lh /path/to/ember*.tar.bz2

# 解压（如果还没解压）
tar -xjf ember_dataset.tar.bz2
```

## 测试流程

1. **运行检查脚本**
   ```bash
   bash train/check_setup.sh
   ```

2. **如果所有检查通过，运行快速测试**
   ```bash
   bash train/test_local.sh
   ```

3. **如果测试通过，准备提交到HPRC**
   ```bash
   # 在HPRC上
   sbatch train/slurm_train.sh
   ```

