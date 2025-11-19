# TAMU HPRC FASTER 系统使用指南

## 系统概述

FASTER是TAMU HPRC的高性能计算集群，支持GPU加速和大规模并行计算。

## 1. 登录系统

```bash
# SSH连接到FASTER登录节点
ssh NetID@faster.tamu.edu

# 或者使用完整域名
ssh NetID@faster.hprc.tamu.edu
```

将 `NetID` 替换为你的TAMU NetID。

## 2. 查看可用模块

```bash
# 查看所有可用模块
module avail

# 查看Python相关模块
module spider Python

# 查看CUDA/GPU相关模块
module spider CUDA
module spider cuDNN
```

## 3. 加载环境模块

### 3.1 加载Python模块

```bash
# 方法1: 加载特定版本的Python（推荐）
module purge  # 清除之前加载的模块
module load GCCcore/12.2.0
module load Python/3.10.8

# 方法2: 查看可用的Python版本
module spider Python/3.10

# 验证Python版本
python3 --version
which python3
```

### 3.2 加载GPU相关模块（如果使用GPU）

```bash
# 加载CUDA
module load CUDA/11.7.0

# 加载cuDNN（深度学习加速库）
module load cuDNN/8.4.1.50-CUDA-11.7.0

# 验证GPU
nvidia-smi
```

### 3.3 加载其他必要模块

```bash
# 如果需要编译C++代码
module load GCC/12.2.0

# 如果需要其他工具
module load git
module load wget
```

## 4. 创建Python虚拟环境

### 方法1: 使用venv（推荐）

```bash
# 切换到工作目录（使用SCRATCH，不要用HOME）
cd $SCRATCH

# 创建项目目录
mkdir ember_training
cd ember_training

# 创建虚拟环境（使用系统site-packages可以访问已安装的模块）
python3 -m venv --system-site-packages venv

# 激活虚拟环境
source venv/bin/activate

# 验证
which python
python --version
```

### 方法2: 使用conda（如果可用）

```bash
# 加载conda模块
module load Anaconda3

# 创建conda环境
conda create -n ember_env python=3.10
conda activate ember_env
```

## 5. 安装Python依赖

```bash
# 确保虚拟环境已激活
source venv/bin/activate

# 升级pip
pip install --upgrade pip

# 安装项目依赖
pip install numpy pandas scikit-learn tqdm

# 安装LightGBM（支持GPU）
pip install lightgbm

# 安装EMBER库
pip install git+https://github.com/endgameinc/ember.git

# 安装其他依赖
pip install pefile lief requests
```

## 6. 准备数据和代码

### 6.1 上传数据到HPRC

```bash
# 在本地机器上使用scp上传
scp -r /path/to/ember2018 NetID@faster.tamu.edu:$SCRATCH/datasets/

# 或者使用rsync（支持断点续传）
rsync -avz --progress /path/to/ember2018 NetID@faster.tamu.edu:$SCRATCH/datasets/
```

### 6.2 上传代码

```bash
# 上传整个项目
scp -r /path/to/CSCE439 NetID@faster.tamu.edu:$SCRATCH/

# 或者使用git clone（如果代码在GitHub上）
cd $SCRATCH
git clone https://github.com/Math-Maniac7/CSCE439.git
```

## 7. 创建SLURM作业脚本

创建 `train_job.sh`:

```bash
#!/bin/bash
#SBATCH --job-name=ember_training
#SBATCH --output=ember_training_%j.out
#SBATCH --error=ember_training_%j.err
#SBATCH --time=24:00:00          # 24小时时间限制
#SBATCH --nodes=1                # 使用1个节点
#SBATCH --ntasks-per-node=1      # 每个节点1个任务
#SBATCH --cpus-per-task=32       # 32个CPU核心
#SBATCH --mem=256G               # 256GB内存
#SBATCH --gres=gpu:1             # 1块GPU
#SBATCH --partition=gpu          # 使用GPU分区（根据FASTER实际分区调整）

# 打印作业信息
echo "Job ID: $SLURM_JOB_ID"
echo "Node: $SLURM_NODELIST"
echo "Start time: $(date)"

# 加载模块
module purge
module load GCCcore/12.2.0
module load Python/3.10.8
module load CUDA/11.7.0
module load cuDNN/8.4.1.50-CUDA-11.7.0

# 设置CUDA设备
export CUDA_VISIBLE_DEVICES=0

# 激活虚拟环境
source $SCRATCH/ember_training/venv/bin/activate

# 设置工作目录
cd $SCRATCH/CSCE439

# 运行训练
python3 train/train_ember_jsonl.py \
    --train-dir $SCRATCH/datasets/ember2018 \
    --test-dir $SCRATCH/datasets/ember2018 \
    --output defender/defender/models/ember_jsonl_model.pickle \
    --use-gpu \
    --n-estimators 1000 \
    --no-memory-limit \
    --sample-ratio 1.0

echo "End time: $(date)"
echo "Training completed!"
```

## 8. 提交作业

```bash
# 提交作业
sbatch train_job.sh

# 查看作业状态
squeue -u $USER

# 查看作业详情
squeue -j <job_id> -l

# 查看作业输出（实时）
tail -f ember_training_<job_id>.out

# 查看错误日志
tail -f ember_training_<job_id>.err
```

## 9. 监控作业

```bash
# 查看所有作业
squeue -u $USER

# 查看特定作业
squeue -j <job_id>

# 查看作业详细信息
scontrol show job <job_id>

# 查看资源使用情况（需要作业运行中）
sstat -j <job_id> --format=JobID,MaxRSS,MaxVMSize,NTasks

# 取消作业
scancel <job_id>

# 取消所有作业
scancel -u $USER
```

## 10. 交互式作业（用于测试和调试）

```bash
# 申请交互式会话（1小时，1个GPU，32GB内存）
srun --time=01:00:00 --gres=gpu:1 --mem=32G --cpus-per-task=8 --pty bash

# 在交互式会话中
module load GCCcore/12.2.0 Python/3.10.8 CUDA/11.7.0
source $SCRATCH/ember_training/venv/bin/activate
cd $SCRATCH/CSCE439

# 可以交互式运行Python
python3 train/train_ember_jsonl.py --train-dir ... --max-samples 1000
```

## 11. 常用命令

### 文件管理

```bash
# 查看磁盘使用
df -h $SCRATCH
du -sh $SCRATCH/*

# 查看配额
quota -s

# 压缩/解压文件
tar -czf dataset.tar.gz dataset/
tar -xzf dataset.tar.gz
```

### 环境管理

```bash
# 查看已加载的模块
module list

# 清除所有模块
module purge

# 保存当前模块配置
module save ember_env

# 恢复保存的模块配置
module restore ember_env
```

### 作业管理

```bash
# 查看作业历史
sacct -u $USER

# 查看特定作业的详细信息
sacct -j <job_id> --format=JobID,JobName,State,ExitCode,Elapsed,MaxRSS

# 查看作业的CPU和内存使用
seff <job_id>
```

## 12. 优化建议

### 12.1 资源请求

- **CPU**: 根据数据大小，32-64核心通常足够
- **内存**: 大数据集建议256GB+
- **GPU**: 如果有GPU，使用`--use-gpu`参数
- **时间**: 完整训练可能需要12-24小时

### 12.2 性能优化

```bash
# 在作业脚本中设置环境变量
export OMP_NUM_THREADS=32        # OpenMP线程数
export MKL_NUM_THREADS=32        # Intel MKL线程数
export NUMEXPR_NUM_THREADS=32    # NumExpr线程数

# LightGBM GPU设置
export CUDA_VISIBLE_DEVICES=0
```

### 12.3 数据I/O优化

```bash
# 如果数据在慢速存储上，考虑复制到本地SSD
# 在作业脚本开始处添加：
cp -r $SCRATCH/datasets/ember2018 $TMPDIR/
# 然后使用 $TMPDIR/ember2018 作为数据路径
```

## 13. 故障排除

### 问题1: 模块找不到

```bash
# 更新模块缓存
module refresh

# 查看模块依赖
module spider Python/3.10.8
```

### 问题2: GPU不可用

```bash
# 检查GPU分区
sinfo | grep gpu

# 检查GPU状态
nvidia-smi

# 确保作业请求了GPU
#SBATCH --gres=gpu:1
```

### 问题3: 内存不足

```bash
# 增加内存请求
#SBATCH --mem=512G

# 或使用分批加载模式
--use-batch --batch-size 100000
```

### 问题4: 作业被取消

```bash
# 检查作业日志
cat ember_training_<job_id>.err

# 检查时间限制
# 增加 --time 参数
```

## 14. 完整示例工作流

```bash
# 1. 登录
ssh NetID@faster.tamu.edu

# 2. 加载模块
module purge
module load GCCcore/12.2.0 Python/3.10.8 CUDA/11.7.0

# 3. 创建环境
cd $SCRATCH
mkdir -p ember_training
cd ember_training
python3 -m venv --system-site-packages venv
source venv/bin/activate

# 4. 安装依赖
pip install --upgrade pip
pip install numpy pandas scikit-learn tqdm lightgbm pefile lief requests
pip install git+https://github.com/endgameinc/ember.git

# 5. 准备代码和数据（上传或git clone）

# 6. 创建作业脚本
cd $SCRATCH/CSCE439
# 编辑 train_job.sh（使用上面的模板）

# 7. 提交作业
sbatch train_job.sh

# 8. 监控
squeue -u $USER
tail -f ember_training_*.out
```

## 15. 参考资源

- HPRC用户指南: https://hprc.tamu.edu/kb/
- FASTER系统文档: https://hprc.tamu.edu/kb/User-Guides/FASTER/
- SLURM文档: https://slurm.schedmd.com/
- 联系支持: hprc-help@tamu.edu

## 16. 快速检查清单

- [ ] 已登录FASTER系统
- [ ] 已加载Python模块
- [ ] 已创建虚拟环境
- [ ] 已安装所有依赖
- [ ] 数据已上传到$SCRATCH
- [ ] 代码已上传或git clone
- [ ] 已创建SLURM作业脚本
- [ ] 已提交作业
- [ ] 正在监控作业状态

