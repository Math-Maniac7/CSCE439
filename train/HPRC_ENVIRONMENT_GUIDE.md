# HPRC 环境使用指南

## 📋 目录

1. [登录系统](#1-登录系统)
2. [查看和加载模块](#2-查看和加载模块)
3. [创建Python虚拟环境](#3-创建python虚拟环境)
4. [激活环境](#4-激活环境)
5. [安装Python包](#5-安装python包)
6. [保存和恢复环境配置](#6-保存和恢复环境配置)
7. [常用命令速查](#7-常用命令速查)

---

## 1. 登录系统

```bash
# SSH连接到FASTER登录节点
ssh NetID@faster.tamu.edu

# 将 NetID 替换为你的TAMU NetID（例如：yafeili945）
```

---

## 2. 查看和加载模块

### 2.1 查看可用模块

```bash
# 查看所有可用模块（输出很多，建议用grep过滤）
module avail

# 查看Python相关模块
module spider Python

# 查看CUDA/GPU相关模块
module spider CUDA

# 查看特定版本的模块
module spider Python/3.10
```

### 2.2 加载模块

```bash
# 清除之前加载的所有模块（推荐先执行）
module purge

# 加载Python模块（需要先加载GCCcore）
module load GCCcore/12.2.0
module load Python/3.10.8

# 加载GPU相关模块（如果使用GPU）
module load CUDA/11.7.0
module load cuDNN/8.4.1.50-CUDA-11.7.0

# 查看已加载的模块
module list
```

### 2.3 常用模块组合

```bash
# 完整的环境设置（Python + GPU）
module purge
module load GCCcore/12.2.0
module load Python/3.10.8
module load CUDA/11.7.0
module load cuDNN/8.4.1.50-CUDA-11.7.0

# 验证
python3 --version
nvidia-smi  # 检查GPU
```

---

## 3. 创建Python虚拟环境

### 方法1: 使用venv（推荐）

```bash
# 1. 切换到工作目录（使用SCRATCH，不要用HOME）
cd $SCRATCH

# 2. 创建项目目录
mkdir -p ember_training
cd ember_training

# 3. 创建虚拟环境
# --system-site-packages: 允许访问系统已安装的包（可选）
python3 -m venv --system-site-packages venv

# 或者不使用系统包（更干净）
python3 -m venv venv
```

### 方法2: 使用conda（如果可用）

```bash
# 1. 加载conda模块
module load Anaconda3

# 2. 创建conda环境
conda create -n ember_env python=3.10

# 3. 激活环境
conda activate ember_env
```

---

## 4. 激活环境

### venv环境

```bash
# 激活虚拟环境
source venv/bin/activate

# 验证（应该显示虚拟环境的路径）
which python
python --version

# 退出环境
deactivate
```

### conda环境

```bash
# 激活conda环境
conda activate ember_env

# 退出环境
conda deactivate
```

---

## 5. 安装Python包

### 5.1 基本安装

```bash
# 确保虚拟环境已激活
source venv/bin/activate  # venv
# 或
conda activate ember_env  # conda

# 升级pip
pip install --upgrade pip

# 安装单个包
pip install numpy

# 安装多个包
pip install numpy pandas scikit-learn

# 从requirements.txt安装
pip install -r requirements.txt
```

### 5.2 安装特定版本的包

```bash
# 安装特定版本
pip install numpy==1.21.6

# 安装最新版本
pip install --upgrade numpy

# 安装预发布版本
pip install --pre numpy
```

### 5.3 从GitHub安装

```bash
# 安装EMBER库（从GitHub）
pip install git+https://github.com/endgameinc/ember.git

# 安装特定分支
pip install git+https://github.com/endgameinc/ember.git@branch_name

# 安装特定commit
pip install git+https://github.com/endgameinc/ember.git@commit_hash
```

### 5.4 安装GPU支持的包

```bash
# 确保CUDA模块已加载
module load CUDA/11.7.0

# 安装LightGBM（支持GPU）
pip install lightgbm

# 安装XGBoost（支持GPU）
pip install xgboost

# 验证GPU支持
python -c "import lightgbm as lgb; print(lgb.__version__)"
```

### 5.5 安装到用户目录（不使用虚拟环境时）

```bash
# 如果不使用虚拟环境，可以安装到用户目录
pip install --user numpy pandas scikit-learn

# 包会安装到 ~/.local/lib/python3.x/site-packages
```

### 5.6 查看已安装的包

```bash
# 列出所有已安装的包
pip list

# 查看特定包的信息
pip show numpy

# 查看包的依赖
pip show numpy | grep Requires

# 导出requirements.txt
pip freeze > requirements.txt
```

### 5.7 卸载包

```bash
# 卸载单个包
pip uninstall numpy

# 卸载多个包
pip uninstall numpy pandas scikit-learn

# 从requirements.txt卸载
pip uninstall -r requirements.txt -y
```

---

## 6. 保存和恢复环境配置

### 6.1 保存模块配置

```bash
# 保存当前加载的模块
module save ember_env

# 查看保存的配置
module savelist

# 恢复保存的配置
module restore ember_env
```

### 6.2 保存Python环境

```bash
# 激活环境
source venv/bin/activate

# 导出requirements.txt
pip freeze > requirements.txt

# 下次恢复环境
source venv/bin/activate
pip install -r requirements.txt
```

### 6.3 创建环境脚本

创建 `setup_env.sh`:

```bash
#!/bin/bash
# 环境设置脚本

# 清除旧模块
module purge

# 加载模块
module load GCCcore/12.2.0
module load Python/3.10.8
module load CUDA/11.7.0

# 激活虚拟环境
source $SCRATCH/ember_training/venv/bin/activate

# 设置环境变量
export CUDA_VISIBLE_DEVICES=0
export OMP_NUM_THREADS=32

echo "Environment setup complete!"
```

使用：
```bash
source setup_env.sh
```

---

## 7. 常用命令速查

### 模块管理

```bash
module list              # 查看已加载的模块
module avail             # 查看所有可用模块
module spider <name>     # 搜索模块
module load <module>     # 加载模块
module unload <module>   # 卸载模块
module purge             # 清除所有模块
module save <name>       # 保存模块配置
module restore <name>    # 恢复模块配置
```

### Python环境

```bash
# venv
python3 -m venv venv              # 创建环境
source venv/bin/activate          # 激活环境
deactivate                        # 退出环境

# conda
conda create -n <name> python=3.10  # 创建环境
conda activate <name>                # 激活环境
conda deactivate                     # 退出环境
conda env list                       # 列出所有环境
conda remove -n <name> --all         # 删除环境
```

### pip命令

```bash
pip install <package>              # 安装包
pip install <package>==<version>   # 安装特定版本
pip uninstall <package>            # 卸载包
pip list                            # 列出所有包
pip show <package>                 # 显示包信息
pip freeze > requirements.txt       # 导出依赖
pip install -r requirements.txt     # 从文件安装
pip search <keyword>                # 搜索包（已弃用）
```

### 环境验证

```bash
# 检查Python版本和路径
python --version
which python

# 检查已安装的包
pip list | grep <package>

# 检查GPU
nvidia-smi

# 检查CUDA
nvcc --version

# 测试导入
python -c "import numpy; print(numpy.__version__)"
python -c "import lightgbm as lgb; print(lgb.__version__)"
```

---

## 8. 完整示例工作流

### 第一次设置环境

```bash
# 1. 登录
ssh NetID@faster.tamu.edu

# 2. 加载模块
module purge
module load GCCcore/12.2.0
module load Python/3.10.8
module load CUDA/11.7.0

# 3. 创建虚拟环境
cd $SCRATCH
mkdir -p ember_training
cd ember_training
python3 -m venv venv

# 4. 激活环境
source venv/bin/activate

# 5. 升级pip
pip install --upgrade pip

# 6. 安装依赖
pip install numpy pandas scikit-learn tqdm
pip install lightgbm
pip install git+https://github.com/endgameinc/ember.git
pip install pefile lief requests

# 7. 验证
python -c "import numpy, pandas, lightgbm; print('All packages installed!')"
```

### 日常使用

```bash
# 1. 登录
ssh NetID@faster.tamu.edu

# 2. 加载模块（或使用保存的配置）
module restore ember_env  # 如果之前保存过
# 或
module purge
module load GCCcore/12.2.0 Python/3.10.8 CUDA/11.7.0

# 3. 激活环境
source $SCRATCH/ember_training/venv/bin/activate

# 4. 开始工作
cd $SCRATCH/CSCE439
python3 train/train_ember_jsonl.py ...
```

---

## 9. 常见问题

### Q: 模块找不到怎么办？

```bash
# 更新模块缓存
module refresh

# 查看模块依赖
module spider Python/3.10.8

# 检查模块是否正确加载
module list
```

### Q: pip安装包失败？

```bash
# 检查网络连接
ping google.com

# 使用国内镜像（如果网络慢）
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple numpy

# 检查pip版本
pip --version

# 升级pip
pip install --upgrade pip
```

### Q: 包安装成功但导入失败？

```bash
# 检查Python路径
which python
python -c "import sys; print(sys.path)"

# 检查包是否在正确的位置
pip show <package> | grep Location

# 重新安装
pip uninstall <package>
pip install <package>
```

### Q: GPU不可用？

```bash
# 检查CUDA模块是否加载
module list | grep CUDA

# 检查GPU
nvidia-smi

# 检查环境变量
echo $CUDA_VISIBLE_DEVICES

# 设置GPU
export CUDA_VISIBLE_DEVICES=0
```

---

## 10. 快速参考卡片

```
┌─────────────────────────────────────────┐
│  HPRC环境快速参考                        │
├─────────────────────────────────────────┤
│  登录: ssh NetID@faster.tamu.edu       │
│  加载模块: module load Python/3.10.8    │
│  创建环境: python3 -m venv venv         │
│  激活环境: source venv/bin/activate     │
│  安装包: pip install <package>         │
│  查看模块: module list                  │
│  查看包: pip list                      │
└─────────────────────────────────────────┘
```

---

## 11. 更多资源

- HPRC官方文档: https://hprc.tamu.edu/kb/
- FASTER系统文档: https://hprc.tamu.edu/kb/User-Guides/FASTER/
- 联系支持: hprc-help@tamu.edu
- 详细指南: `train/HPRC_FASTER_GUIDE.md`

