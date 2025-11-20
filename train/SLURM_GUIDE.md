# SLURM作业提交指南

## 快速开始

### 1. 提交作业

```bash
# 进入项目目录
cd /scratch/user/yafeili/704/CSCE439

# 提交SLURM作业
sbatch train/slurm_train.sh
```

### 2. 查看作业状态

```bash
# 查看你的所有作业
squeue -u yafeili

# 查看特定作业
squeue -j <job_id>

# 查看作业详细信息
scontrol show job <job_id>
```

### 3. 查看日志

```bash
# 查看输出日志（实时）
tail -f /scratch/user/yafeili/704/defenceOutput/slurm_training_<job_id>.out

# 查看错误日志
tail -f /scratch/user/yafeili/704/defenceOutput/slurm_training_<job_id>.err

# 查看最新的日志
ls -t /scratch/user/yafeili/704/defenceOutput/slurm_training_*.out | head -1 | xargs tail -f
```

## 常用命令

### 作业管理

```bash
# 提交作业
sbatch train/slurm_train.sh

# 查看作业状态
squeue -u yafeili

# 查看所有作业（包括已完成）
squeue -u yafeili -a

# 取消作业
scancel <job_id>

# 取消所有作业
scancel -u yafeili

# 查看作业历史
sacct -u yafeili

# 查看作业详细信息
sacct -j <job_id> --format=JobID,JobName,State,ExitCode,Elapsed,MaxRSS,NodeList
```

### 资源监控

```bash
# 查看作业的资源使用情况
seff <job_id>

# 查看作业的实时资源使用
sstat -j <job_id> --format=JobID,MaxRSS,MaxVMSize,NTasks

# 查看GPU使用情况（在计算节点上）
nvidia-smi
```

### 日志查看

```bash
# 查看最新的输出日志
tail -100 $(ls -t /scratch/user/yafeili/704/defenceOutput/slurm_training_*.out | head -1)

# 查看最新的错误日志
tail -100 $(ls -t /scratch/user/yafeili/704/defenceOutput/slurm_training_*.err | head -1)

# 搜索日志中的关键词
grep -i "error" /scratch/user/yafeili/704/defenceOutput/slurm_training_*.out
grep -i "completed" /scratch/user/yafeili/704/defenceOutput/slurm_training_*.out
```

## 修改作业参数

如果需要修改资源请求，编辑 `train/slurm_train.sh`：

```bash
# 修改时间限制
#SBATCH --time=72:00:00  # 改为72小时

# 修改内存
#SBATCH --mem=512G        # 改为512GB

# 修改CPU核心数
#SBATCH --cpus-per-task=64  # 改为64核心

# 修改GPU数量
#SBATCH --gres=gpu:2      # 改为2块GPU

# 修改分区（根据FASTER实际分区）
#SBATCH --partition=gpu   # 或其他分区名称
```

## 查看可用分区和资源

```bash
# 查看所有分区
sinfo

# 查看GPU分区
sinfo | grep gpu

# 查看分区详细信息
sinfo -p gpu -o "%P %l %D %T %N %G"
```

## 交互式作业（用于测试）

如果需要交互式测试，可以使用：

```bash
# 申请交互式会话（1小时，1个GPU，32GB内存）
srun --time=01:00:00 --gres=gpu:1 --mem=32G --cpus-per-task=8 --pty bash

# 在交互式会话中
module load GCCcore/12.2.0 Python/3.10.8 CUDA/11.7.0
source ~/venv/bin/activate
cd /scratch/user/yafeili/704/CSCE439

# 可以交互式运行Python或测试
python3 train/train_iterative.py --model-id model1 --dataset-dir ... --max-samples 1000
```

## 故障排除

### 问题1: 作业一直在排队（PENDING）

```bash
# 查看排队原因
squeue -j <job_id> -o "%.18i %.9P %.8j %.8u %.2t %.10M %.6D %R"

# 常见原因：
# - 资源不足（内存/GPU）
# - 时间限制太长
# - 分区选择错误
```

### 问题2: 作业失败（FAILED）

```bash
# 查看错误日志
cat /scratch/user/yafeili/704/defenceOutput/slurm_training_<job_id>.err

# 查看退出代码
sacct -j <job_id> --format=JobID,ExitCode,State
```

### 问题3: 作业被取消（CANCELLED）

```bash
# 检查时间限制
# 如果作业运行时间超过--time限制，会被自动取消

# 检查内存使用
# 如果超过--mem限制，会被OOM killer终止
```

## 完整工作流示例

```bash
# 1. 进入项目目录
cd /scratch/user/yafeili/704/CSCE439

# 2. 提交作业
sbatch train/slurm_train.sh
# 输出: Submitted batch job 12345678

# 3. 查看作业状态
squeue -u yafeili
# 输出: JOBID PARTITION NAME USER ST TIME NODES NODELIST(REASON)
#       12345678 gpu defence_training yafeili R 0:05 1 node001

# 4. 查看实时日志
tail -f /scratch/user/yafeili/704/defenceOutput/slurm_training_12345678.out

# 5. 查看作业完成后的资源使用
seff 12345678

# 6. 查看训练结果
ls -lh /scratch/user/yafeili/704/defenceOutput/trained_models_*/
```

## 提示

1. **时间限制**: 根据实际训练时间设置，可以设置长一些（如48-72小时）
2. **内存**: 大数据集建议256GB+
3. **GPU**: 确保请求了GPU（`--gres=gpu:1`）
4. **日志**: 定期查看日志确保训练正常进行
5. **检查点**: 如果训练时间很长，考虑添加检查点保存中间结果

