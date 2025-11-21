# HPRC官方指南 - 创建环境和提交作业

根据 [HPRC新用户信息页面](https://hprc.tamu.edu/user_services/new_user_information.html) 整理的完整流程。

## 📚 HPRC资源

- **用户指南**: https://hprc.tamu.edu/kb/
- **FASTER系统文档**: https://hprc.tamu.edu/kb/User-Guides/FASTER/
- **技术支持**: hprc-help@tamu.edu 或 (979) 845-0219
- **YouTube频道**: https://www.youtube.com/texasamhprc

## 🚀 完整工作流程

### 第一部分：创建Python虚拟环境

#### 步骤1: 登录系统

```bash
ssh yafeili@faster.tamu.edu
```

#### 步骤2: 加载Python模块

```bash
# 清除之前加载的模块
module purge

# 加载Python模块（需要先加载GCCcore）
module load GCCcore/12.2.0
module load Python/3.10.8

# 验证
python3 --version
which python3
```

#### 步骤3: 创建虚拟环境

**选项A: 在HOME目录创建（推荐，有备份）**

```bash
cd ~
python3 -m venv venv

# 验证创建
ls -la venv
```

**选项B: 在SCRATCH目录创建（空间大，但无备份）**

```bash
cd $SCRATCH
python3 -m venv venv

# 验证创建
ls -la $SCRATCH/venv
```

#### 步骤4: 激活虚拟环境

```bash
# 如果在HOME创建
source ~/venv/bin/activate

# 如果在SCRATCH创建
source $SCRATCH/venv/bin/activate

# 验证激活（命令行前面应该有(venv)标记）
which python
# 应该显示: /home/yafeili/venv/bin/python
```

#### 步骤5: 安装Python包

```bash
# 确保虚拟环境已激活（看到(venv)标记）

# 升级pip
pip install --upgrade pip

# 安装依赖包
pip install numpy pandas scikit-learn tqdm lightgbm pefile lief requests

# 安装EMBER库（从GitHub）
pip install git+https://github.com/endgameinc/ember.git

# 验证安装
python -c "import numpy, pandas, sklearn, lightgbm, ember; print('✓ 所有包OK!')"
```

---

### 第二部分：提交SLURM作业

根据HPRC文档，SLURM是FASTER系统的批处理作业调度系统。

#### 步骤1: 准备作业脚本

我们已经有准备好的脚本：`train/slurm_train.sh`

#### 步骤2: 检查脚本配置

```bash
# 查看SLURM脚本
cat train/slurm_train.sh | head -20

# 确认关键配置：
# - 作业名称
# - 资源请求（CPU、内存、GPU）
# - 时间限制
# - 分区名称
```

#### 步骤3: 提交作业

```bash
# 在项目目录下
cd /scratch/user/yafeili/CSCE439

# 提交作业
sbatch train/slurm_train.sh

# 输出示例：
# Submitted batch job 12345678
```

#### 步骤4: 查看作业状态

```bash
# 查看你的所有作业
squeue -u yafeili

# 查看作业详细信息
scontrol show job <job_id>

# 查看作业在队列中的位置
squeue -j <job_id> -o "%.18i %.20j %.8u %.2t %.10M %.6D %R %.20S"
```

#### 步骤5: 监控作业

```bash
# 查看输出日志（实时）
tail -f /scratch/user/yafeili/704/defenceOutput/slurm_training_<job_id>.out

# 查看错误日志
tail -f /scratch/user/yafeili/704/defenceOutput/slurm_training_<job_id>.err
```

---

## 📋 SLURM作业配置说明

### 基本配置（我们的脚本中）

```bash
#SBATCH --job-name=defence_training    # 作业名称
#SBATCH --time=48:00:00                 # 时间限制：48小时
#SBATCH --nodes=1                       # 节点数：1个
#SBATCH --ntasks-per-node=1             # 每节点任务数：1个
#SBATCH --cpus-per-task=32              # CPU核心数：32个
#SBATCH --mem=256G                      # 内存：256GB
#SBATCH --gres=gpu:1                    # GPU：1块
#SBATCH --partition=gpu                 # 分区：gpu分区
```

### 根据需求调整

如果需要更多资源或更长时间：

```bash
# 更多内存
#SBATCH --mem=512G

# 更多CPU
#SBATCH --cpus-per-task=64

# 更长时间
#SBATCH --time=72:00:00

# 更多GPU
#SBATCH --gres=gpu:2
```

---

## 🔍 常用SLURM命令

### 作业管理

```bash
# 提交作业
sbatch train/slurm_train.sh

# 查看作业状态
squeue -u yafeili

# 查看特定作业
squeue -j <job_id>

# 查看作业详情
scontrol show job <job_id>

# 取消作业
scancel <job_id>

# 取消所有作业
scancel -u yafeili

# 查看作业历史
sacct -u yafeili

# 查看资源使用
seff <job_id>
```

### 资源查看

```bash
# 查看所有分区
sinfo

# 查看GPU分区
sinfo | grep gpu

# 查看节点使用情况
sinfo -N -l

# 查看你的账户配额
quota -s
```

---

## ✅ 完整流程检查清单

### 环境创建

- [ ] 已登录FASTER系统
- [ ] 已加载Python模块（`module load GCCcore/12.2.0 Python/3.10.8`）
- [ ] 已创建虚拟环境（`python3 -m venv ~/venv`）
- [ ] 虚拟环境存在（`ls ~/venv`）
- [ ] 已激活虚拟环境（看到`(venv)`标记）
- [ ] 已安装所有依赖包
- [ ] 已验证包安装（能导入numpy, pandas, lightgbm, ember）

### 作业提交

- [ ] 已在项目目录（`/scratch/user/yafeili/CSCE439`）
- [ ] SLURM脚本路径正确（`train/slurm_train.sh`）
- [ ] 数据集路径正确（`/scratch/user/yafeili/704/dataset`）
- [ ] 已提交作业（`sbatch train/slurm_train.sh`）
- [ ] 获得作业ID
- [ ] 作业状态为PENDING或RUNNING
- [ ] 知道如何查看日志

---

## 🆘 故障排除

### 问题1: 模块找不到

```bash
# 更新模块缓存
module refresh

# 查看可用模块
module spider Python

# 查看模块依赖
module spider Python/3.10.8
```

### 问题2: 虚拟环境创建失败

```bash
# 检查Python是否正确加载
which python3
python3 --version

# 检查磁盘空间
df -h ~
df -h $SCRATCH

# 尝试在SCRATCH创建
cd $SCRATCH
python3 -m venv venv
```

### 问题3: 作业一直排队

```bash
# 查看排队原因
squeue -j <job_id> -o "%R"

# 查看资源使用情况
sinfo -p gpu

# 可能需要调整资源请求（减少内存或CPU）
```

### 问题4: 作业失败

```bash
# 查看错误日志
cat /scratch/user/yafeili/704/defenceOutput/slurm_training_<job_id>.err

# 查看退出代码
sacct -j <job_id> --format=ExitCode,State
```

---

## 📖 官方资源

根据 [HPRC新用户信息页面](https://hprc.tamu.edu/user_services/new_user_information.html)：

1. **快速入门指南**: 在知识库中可用
2. **培训课程**: 每学期提供短期课程
3. **YouTube频道**: 包含入门和Open OnDemand视频
4. **FAQ页面**: 常见问题和解决方案
5. **技术支持**: helpdesk@hprc.tamu.edu 或 (979) 845-0219

---

## 🎯 快速参考

### 创建环境（一次性）

```bash
module purge
module load GCCcore/12.2.0 Python/3.10.8
python3 -m venv ~/venv
source ~/venv/bin/activate
pip install --upgrade pip
pip install numpy pandas scikit-learn tqdm lightgbm pefile lief requests
pip install git+https://github.com/endgameinc/ember.git
```

### 提交作业（每次训练）

```bash
cd /scratch/user/yafeili/CSCE439
sbatch train/slurm_train.sh
```

### 查看状态（日常）

```bash
squeue -u yafeili
tail -f /scratch/user/yafeili/704/defenceOutput/slurm_training_*.out
```

