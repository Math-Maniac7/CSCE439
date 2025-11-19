# EMBER模型训练和部署完整指南

本文档说明如何使用EMBER JSONL数据集训练新的防御模型，并将其部署到Docker中。

## 📁 创建的文件

### 1. 训练脚本
- **`train/train_ember_jsonl.py`**: 从JSONL格式的EMBER数据集训练模型的完整脚本
- **`train/train_example.sh`**: 快速训练示例脚本（交互式）
- **`train/README_EMBER_TRAINING.md`**: 详细的训练文档

### 2. 模型类
- **`defender/defender/models/ember_jsonl_model.py`**: 部署用的模型类，可以从原始PE文件字节进行预测

### 3. 更新的文件
- **`defender/defender/__main__.py`**: 添加了对新模型的支持
- **`defender/Dockerfile`**: 更新以安装ember库
- **`defender/docker-requirements.txt`**: 添加了ember库的安装说明

## 🚀 快速开始

### 步骤1: 训练模型

#### 方法A: 使用示例脚本（推荐）

```bash
cd /Users/felix/Documents/704/code/CSCE439
./train/train_example.sh
```

脚本会提示你选择数据集，然后自动开始训练。

#### 方法B: 直接运行Python脚本

```bash
cd /Users/felix/Documents/704/code/CSCE439

# 使用ember2018数据集训练
python train/train_ember_jsonl.py \
    --train-dir /Users/felix/Documents/704/dataset/ember2018 \
    --test-dir /Users/felix/Documents/704/dataset/ember2018 \
    --output defender/defender/models/ember_jsonl_model.pickle \
    --max-samples 50000
```

#### 方法C: 快速测试（使用少量数据）

```bash
python train/train_ember_jsonl.py \
    --train-dir /Users/felix/Documents/704/dataset/ember2018 \
    --output defender/defender/models/ember_jsonl_model.pickle \
    --max-samples 10000
```

### 步骤2: 验证模型

训练完成后，脚本会显示性能指标：
- **FPR (假阳性率)**: 应该 ≤ 0.01 (1%)
- **TPR (真阳性率)**: 应该 ≥ 0.95 (95%)

### 步骤3: 部署到Docker

#### 3.1 确保模型文件在正确位置

训练完成后，模型文件应该已经在：
```
defender/defender/models/ember_jsonl_model.pickle
```

#### 3.2 构建Docker镜像

```bash
cd defender
docker build -t malware-defense-ember .
```

#### 3.3 运行Docker容器

```bash
docker run --memory=1g -p 8080:8080 \
    -e DF_MODEL_NAME="ember_jsonl" \
    -e DF_MODEL_GZ_PATH="models/ember_jsonl_model.pickle" \
    -e DF_MODEL_THRESH=0.5 \
    malware-defense-ember
```

#### 3.4 测试API

```bash
# 检查模型信息
curl -X GET http://localhost:8080/model

# 测试文件检测
curl -X POST --data-binary @test.exe http://localhost:8080/ \
    -H "Content-Type: application/octet-stream"
```

## 📊 训练参数说明

### 必需参数
- `--train-dir`: 训练数据目录（包含train_features_*.jsonl文件）

### 可选参数
- `--test-dir`: 测试数据目录（如果不提供，会从训练集分割）
- `--output`: 输出模型文件路径（默认：`ember_model.pickle`）
- `--max-samples`: 每个文件最大加载样本数（用于快速测试）
- `--test-split`: 训练/测试集分割比例（默认：0.2）
- `--random-state`: 随机种子（默认：42）

## 🔧 模型配置

### 环境变量

在Docker运行时，可以通过环境变量配置模型：

```bash
DF_MODEL_NAME="ember_jsonl"              # 模型名称
DF_MODEL_GZ_PATH="models/ember_jsonl_model.pickle"  # 模型路径
DF_MODEL_THRESH=0.5                      # 分类阈值
```

### 模型阈值调整

如果FPR或TPR不满足要求，可以调整阈值：

- **降低阈值** (例如 0.3): 提高TPR，但可能增加FPR
- **提高阈值** (例如 0.7): 降低FPR，但可能降低TPR

在训练脚本中，可以通过修改`EMBERModel`的初始化来调整阈值。

## 📝 数据集说明

### 可用数据集

项目中有三个EMBER数据集目录：

1. **ember2018**: `/Users/felix/Documents/704/dataset/ember2018`
2. **ember_2017_2**: `/Users/felix/Documents/704/dataset/ember_2017_2`
3. **ember_dataset**: `/Users/felix/Documents/704/dataset/ember_dataset/ember`

### 数据格式

每个数据集包含：
- `train_features_0.jsonl` 到 `train_features_5.jsonl`: 训练数据
- `test_features.jsonl`: 测试数据

每个JSONL文件每行一个JSON对象，包含：
- `label`: 0=良性, 1=恶意
- `histogram`: 256维特征
- `byteentropy`: 256维特征
- `strings`: 104维特征
- `general`: 10维特征
- `header`: 62维特征
- `section`: 255维特征
- `imports`: 1280维特征
- `exports`: 128维特征
- `datadirectories`: 30维特征

## ⚠️ 注意事项

1. **内存使用**: 训练大数据集时可能需要大量内存（建议至少8GB）
2. **训练时间**: 完整数据集训练可能需要数小时
3. **模型大小**: 训练好的模型文件可能较大（几百MB）
4. **Docker限制**: 确保Docker镜像（未压缩）不超过1GB
5. **特征一致性**: 部署时必须使用与训练时相同的特征提取器（EMBER version=2）

## 🐛 故障排除

### 问题1: 内存不足

**解决方案**: 使用`--max-samples`参数限制数据量

```bash
python train/train_ember_jsonl.py \
    --train-dir /path/to/data \
    --max-samples 10000
```

### 问题2: 模型加载失败

**解决方案**: 
- 检查模型文件路径是否正确
- 确保pickle文件完整
- 检查文件权限

### 问题3: 特征维度不匹配

**解决方案**: 
- 确保使用EMBER特征提取器版本2
- 检查模型训练时使用的特征提取器版本

### 问题4: Docker构建失败

**解决方案**:
- 确保网络连接正常（需要从GitHub安装ember库）
- 检查Dockerfile中的依赖安装顺序

## 📚 相关文档

- 详细训练文档: `train/README_EMBER_TRAINING.md`
- 防御者挑战要求: `defender/README.md`
- 项目主README: `README.md`

## 🎯 挑战要求回顾

### 防御者挑战要求

- ✅ **FPR ≤ 1%**: 假阳性率不超过1%
- ✅ **TPR ≥ 95%**: 真阳性率至少95%
- ✅ **内存 ≤ 1GB**: Docker容器内存限制
- ✅ **响应时间 ≤ 5秒**: 每个样本处理时间

### 模型特点

- 使用EMBER特征（2381维）
- 基于RandomForest分类器
- 支持从原始PE文件字节进行预测
- 完全兼容现有Docker部署架构

## 📞 支持

如有问题，请检查：
1. 训练日志输出
2. Docker容器日志
3. API响应错误信息

祝训练顺利！🎉

