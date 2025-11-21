# GPU节点配置指南 - FASTER集群

## 问题诊断

### 症状
- 作业请求了GPU，但运行在CPU节点（如fc031）
- nvidia-smi报错：`libnvidia-ml.so` stub library
- 作业实际没有GPU可用

### 根本原因
资源请求过高（32 CPU + 256GB），GPU节点无法满足，SLURM自动fallback到CPU分区。

## GPU节点规格（FASTER集群）

根据FASTER集群配置：
- **CPU核心数**: 8-16核心（不是32个）
- **内存**: 64-128GB（不是256GB）
- **GPU**: 通常1-4块GPU

## 正确的SLURM配置

```bash
#SBATCH --partition=gpu          # GPU分区
#SBATCH --gres=gpu:1             # 1块GPU
#SBATCH --constraint=gpu         # 强制GPU节点（防止fallback）

# 保守资源请求
#SBATCH --cpus-per-task=8        # 8核（匹配GPU节点）
#SBATCH --mem=64G                # 64GB（匹配GPU节点）
#SBATCH --time=48:00:00
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
```

## 验证GPU节点

### 方法1: 交互式测试

```bash
# 申请GPU节点交互式会话
srun -p gpu --gres=gpu:1 --pty bash

# 进入后测试GPU
nvidia-smi

# 应该看到GPU信息，而不是错误
```

### 方法2: 检查作业运行的节点

```bash
# 查看作业详情
scontrol show job <job_id>

# 检查：
# - NodeList: 应该显示GPU节点名称（不是fc031这样的CPU节点）
# - GRES: 应该显示 gpu:1

# 或者查看节点信息
scontrol show node <node_name>
```

### 方法3: 在作业中检查GPU

```bash
# 在SLURM脚本中添加GPU检查
echo "Checking GPU..."
nvidia-smi --list-gpus

# 或者
python3 -c "import torch; print(torch.cuda.is_available())"
```

## 资源请求调整建议

| 需求 | 原始请求 | 建议请求 | 原因 |
|------|---------|---------|------|
| CPU | 32核心 | 8核心 | GPU节点通常8-16核 |
| 内存 | 256GB | 64GB | GPU节点通常64-128GB |
| GPU | 1块 | 1块 | ✓ 保持不变 |
| 时间 | 48小时 | 48小时 | ✓ 保持不变 |

### 如果确实需要更多资源

```bash
# 选项1: 使用更多GPU节点（如果允许）
#SBATCH --nodes=2
#SBATCH --gres=gpu:2

# 选项2: 降低batch size，减少内存需求
#SBATCH --mem=128G  # 最多128GB

# 选项3: 使用CPU节点但不需要GPU
#SBATCH --partition=cpu
#SBATCH --gres=gpu:0  # 明确不使用GPU
```

## 常见错误和解决方案

### 错误1: 作业在CPU节点运行

**症状**: 作业运行在fc031等CPU节点

**原因**: 资源请求过高，无法调度到GPU节点

**解决**: 降低CPU和内存请求，添加`--constraint=gpu`

### 错误2: nvidia-smi失败

**症状**: `libnvidia-ml.so` stub library错误

**原因**: 在CPU节点上运行，没有GPU驱动

**解决**: 确保作业运行在GPU节点（使用上面的配置）

### 错误3: 作业一直排队

**症状**: 作业状态一直是PENDING

**原因**: GPU资源不足或请求的资源仍然太高

**解决**: 
- 进一步降低资源请求
- 查看GPU分区使用情况：`sinfo -p gpu`
- 查看可用GPU：`squeue -p gpu`

## 当前脚本配置

我们的`slurm_train.sh`已经配置为：
- ✅ GPU分区
- ✅ 8 CPU核心
- ✅ 64GB内存
- ✅ 1块GPU
- ✅ 强制GPU节点约束

## 验证步骤

1. **提交作业后检查节点**:
   ```bash
   squeue -u yafeili
   scontrol show job <job_id> | grep NodeList
   ```

2. **检查是否是GPU节点**:
   ```bash
   scontrol show node <node_name> | grep -E "Gres|Partitions"
   ```
   
   应该看到：
   ```
   Gres=gpu:1
   Partitions=gpu
   ```

3. **在作业中验证GPU**:
   ```bash
   tail -f slurm_training_*.out | grep -i gpu
   ```

## 总结

关键要点：
1. ✅ GPU节点资源有限，不要请求过多
2. ✅ 使用`--constraint=gpu`强制GPU节点
3. ✅ 保守的资源请求（8 CPU, 64GB RAM）
4. ✅ 验证作业确实在GPU节点上运行

