# EMBER JSONL 模型训练指南

本指南说明如何使用EMBER JSONL数据集训练恶意软件检测模型。

## 数据集格式

EMBER数据集使用JSONL格式（每行一个JSON对象），包含以下特征：

- `histogram`: 256维字节直方图
- `byteentropy`: 256维字节熵
- `strings`: 104维字符串特征
- `general`: 10维通用特征
- `header`: 62维PE头特征
- `section`: 255维节特征
- `imports`: 1280维导入特征
- `exports`: 128维导出特征
- `datadirectories`: 30维数据目录特征

总共2381维特征。

## 训练步骤

### 1. 准备数据

确保你的数据集目录包含以下文件：
- `train_features_0.jsonl`
- `train_features_1.jsonl`
- `train_features_2.jsonl`
- ... (更多训练文件)
- `test_features.jsonl` (可选，用于测试)

### 2. 安装依赖

```bash
pip install numpy pandas scikit-learn tqdm
```

### 3. 运行训练脚本

基本用法：

```bash
python train/train_ember_jsonl.py \
    --train-dir /Users/felix/Documents/704/dataset/ember2018 \
    --output defender/defender/models/ember_model.pickle
```

完整参数：

```bash
python train/train_ember_jsonl.py \
    --train-dir /path/to/train/data \
    --test-dir /path/to/test/data \
    --output model.pickle \
    --max-samples 100000 \
    --test-split 0.2 \
    --random-state 42
```

参数说明：
- `--train-dir`: 训练数据目录（必需）
- `--test-dir`: 测试数据目录（可选，如果不提供则从训练集分割）
- `--output`: 输出模型文件路径（默认：`ember_model.pickle`）
- `--max-samples`: 每个文件最大加载样本数（用于快速测试，默认：全部）
- `--test-split`: 训练/测试集分割比例（默认：0.2）
- `--random-state`: 随机种子（默认：42）

### 4. 训练示例

使用ember2018数据集训练：

```bash
cd /Users/felix/Documents/704/code/CSCE439

python train/train_ember_jsonl.py \
    --train-dir /Users/felix/Documents/704/dataset/ember2018 \
    --test-dir /Users/felix/Documents/704/dataset/ember2018 \
    --output defender/defender/models/ember_jsonl_model.pickle \
    --max-samples 50000
```

快速测试（使用少量数据）：

```bash
python train/train_ember_jsonl.py \
    --train-dir /Users/felix/Documents/704/dataset/ember2018 \
    --output defender/defender/models/ember_jsonl_model.pickle \
    --max-samples 10000
```

## 模型部署

### 1. 将模型文件放在正确位置

训练完成后，将模型文件复制到defender目录：

```bash
cp ember_model.pickle defender/defender/models/ember_jsonl_model.pickle
```

### 2. 配置环境变量

在Dockerfile或运行时设置：

```bash
export DF_MODEL_NAME="ember_jsonl"
export DF_MODEL_GZ_PATH="models/ember_jsonl_model.pickle"
export DF_MODEL_THRESH=0.5
```

### 3. 构建Docker镜像

```bash
cd defender
docker build -t malware-defense-ember .
```

### 4. 运行Docker容器

```bash
docker run --memory=1g -p 8080:8080 \
    -e DF_MODEL_NAME="ember_jsonl" \
    -e DF_MODEL_GZ_PATH="models/ember_jsonl_model.pickle" \
    -e DF_MODEL_THRESH=0.5 \
    malware-defense-ember
```

### 5. 测试API

```bash
# 检查模型信息
curl -X GET http://localhost:8080/model

# 测试文件检测
curl -X POST --data-binary @test.exe http://localhost:8080/ \
    -H "Content-Type: application/octet-stream"
```

## 性能指标

训练脚本会输出以下性能指标：

- **准确率 (Accuracy)**: 整体分类准确率
- **召回率 (Recall/TPR)**: 真阳性率，目标 ≥ 0.95
- **精确率 (Precision)**: 预测为恶意软件中的真实比例
- **F1分数**: 精确率和召回率的调和平均
- **假阳性率 (FPR)**: 目标 ≤ 0.01
- **假阴性率 (FNR)**: 漏检率

## 注意事项

1. **内存使用**: 训练大数据集时可能需要大量内存，可以使用`--max-samples`限制每个文件的样本数
2. **训练时间**: 完整数据集训练可能需要数小时，建议先用小数据集测试
3. **模型大小**: 训练好的模型文件可能较大（几百MB），确保Docker镜像不超过1GB限制
4. **特征一致性**: 部署时使用的特征提取器必须与训练时一致（EMBER feature_version=2）

## 故障排除

### 问题：内存不足

解决方案：使用`--max-samples`参数限制数据量，或增加系统内存。

### 问题：模型加载失败

解决方案：确保模型文件路径正确，且pickle文件完整。

### 问题：特征维度不匹配

解决方案：确保使用正确的EMBER特征提取器版本（version=2）。

