# EMBER数据集下载指南

## 数据集名称

**EMBER (Endgame Malware BEnchmark for Research)**

## 数据集版本

项目支持以下EMBER数据集版本：
- **EMBER 2017**: 2017年版本
- **EMBER 2018**: 2018年版本（推荐）

## 下载地址

### 官方下载

EMBER数据集由Endgame（现为Elastic）发布，可以通过以下方式获取：

1. **GitHub官方仓库**:
   - 仓库地址: https://github.com/elastic/ember
   - 数据集下载链接通常在README或releases中

2. **直接下载链接**（如果可用）:
   - EMBER 2017: https://github.com/elastic/ember/releases
   - EMBER 2018: https://github.com/elastic/ember/releases

3. **学术论文数据**:
   - 论文: "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models"
   - 数据集通常与论文一起发布

### 数据集文件结构

下载后，数据集应该包含以下JSONL文件：

**训练数据**:
- `train_features_0.jsonl`
- `train_features_1.jsonl`
- `train_features_2.jsonl`
- `train_features_3.jsonl`
- `train_features_4.jsonl`
- `train_features_5.jsonl`

**测试数据**:
- `test_features.jsonl`

### 数据集大小

- 每个训练文件: 约200-300MB（压缩）或更大（解压后）
- 完整数据集: 约10-20GB（解压后）
- 总样本数: 约100-200万样本

## 下载步骤

### 方法1: 从GitHub下载（推荐）

```bash
# 1. 克隆或访问EMBER仓库
git clone https://github.com/elastic/ember.git
cd ember

# 2. 查看README了解下载链接
# 或者直接下载数据集文件

# 3. 数据集通常以压缩包形式提供
# 下载后解压到指定目录
```

### 方法2: 直接下载链接

如果GitHub releases中有直接下载链接：

```bash
# 创建数据集目录
mkdir -p /path/to/datasets/ember2018
cd /path/to/datasets/ember2018

# 下载训练数据（示例，实际链接需要从GitHub获取）
# wget https://github.com/elastic/ember/releases/download/v1.0/train_features_0.jsonl
# wget https://github.com/elastic/ember/releases/download/v1.0/train_features_1.jsonl
# ... (其他文件)

# 下载测试数据
# wget https://github.com/elastic/ember/releases/download/v1.0/test_features.jsonl
```

### 方法3: 使用Python脚本下载

```python
import requests
from pathlib import Path

# 数据集URL（需要从GitHub获取实际链接）
base_url = "https://github.com/elastic/ember/releases/download/v1.0/"
output_dir = Path("/path/to/datasets/ember2018")
output_dir.mkdir(parents=True, exist_ok=True)

# 下载训练文件
for i in range(6):
    filename = f"train_features_{i}.jsonl"
    url = base_url + filename
    print(f"Downloading {filename}...")
    response = requests.get(url, stream=True)
    with open(output_dir / filename, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)

# 下载测试文件
filename = "test_features.jsonl"
url = base_url + filename
print(f"Downloading {filename}...")
response = requests.get(url, stream=True)
with open(output_dir / filename, 'wb') as f:
    for chunk in response.iter_content(chunk_size=8192):
        f.write(chunk)
```

## 验证数据集

下载后，验证数据集完整性：

```bash
# 检查文件是否存在
ls -lh /path/to/datasets/ember2018/

# 应该看到：
# train_features_0.jsonl
# train_features_1.jsonl
# ...
# train_features_5.jsonl
# test_features.jsonl

# 检查文件大小（应该都是几百MB）
du -h /path/to/datasets/ember2018/*.jsonl

# 检查文件格式（每行应该是有效的JSON）
head -n 1 /path/to/datasets/ember2018/train_features_0.jsonl | python3 -m json.tool
```

## 使用数据集

下载完成后，使用训练脚本：

```bash
python3 train/train_ember_jsonl.py \
    --train-dir /path/to/datasets/ember2018 \
    --test-dir /path/to/datasets/ember2018 \
    --output defender/defender/models/ember_jsonl_model.pickle
```

## 备用下载源

如果GitHub下载较慢，可以尝试：

1. **学术镜像**: 某些大学或研究机构可能有镜像
2. **Kaggle**: 有时会有社区上传的版本
3. **Google Drive / OneDrive**: 可能有研究者分享的链接

## 注意事项

1. **文件大小**: 数据集很大，确保有足够的磁盘空间（至少50GB）
2. **下载时间**: 完整下载可能需要数小时，取决于网络速度
3. **文件完整性**: 下载后建议验证文件完整性（如果有提供checksum）
4. **许可协议**: 确保遵守EMBER数据集的许可协议

## 快速测试（小数据集）

如果只需要快速测试，可以：

1. 只下载部分训练文件（例如只下载train_features_0.jsonl）
2. 使用`--max-samples`参数限制样本数

```bash
# 只使用部分数据快速测试
python3 train/train_ember_jsonl.py \
    --train-dir /path/to/datasets/ember2018 \
    --output model.pickle \
    --max-samples 10000
```

## 相关链接

- EMBER GitHub: https://github.com/elastic/ember
- EMBER论文: 搜索 "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models"
- MLsec.io: https://mlsec.io (可能需要注册)

## 如果找不到下载链接

如果GitHub上没有直接的下载链接，可以：

1. 查看GitHub Issues中是否有下载链接
2. 联系论文作者或Endgame/Elastic
3. 使用EMBER Python库生成特征（如果有原始PE文件）

```python
from ember import PEFeatureExtractor
import json

extractor = PEFeatureExtractor(2)
features = extractor.feature_vector(pe_file_bytes)
# 然后保存为JSONL格式
```

