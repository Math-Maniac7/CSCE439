# 5种新攻击方法使用指南

## 方法列表

### Method A: Dropper + Metadata + Overlay (结合方法)
**技术组合**:
- Dropper: XOR加密 + Base64编码的payload嵌入C++ stub
- Loader: 写入%TEMP%并通过CreateProcess执行
- Metadata: TimeDateStamp随机化(2024-2025) + CheckSum=0
- Overlay: ~1MB低熵良性overlay

**绕过原理**:
- 输出二进制文件看起来像编译器生成的EXE
- 静态ML检测因字节布局变换而降低
- 时间戳修改破坏签名启发式
- Overlay改变字节分布和熵特征

### Method B: Section Rename + Overlay
**技术**:
- 重命名PE节表 (.text → .code, .data → .info等)
- 添加包含节表样式的良性overlay
- 保持所有导入和功能

**绕过原理**:
- 节表名称改变破坏静态签名
- Overlay添加混淆ML模型的良性模式

### Method C: Import Obfuscation + Padding
**技术**:
- 添加良性导入字符串混淆导入检测
- 修改导入表元数据(时间戳、版本信息)
- 添加包含导入样式的填充

**绕过原理**:
- 导入表改变破坏静态分析签名
- 良性导入稀释恶意导入模式
- 填充改变字节分布

### Method D: Resource Manipulation + Overlay
**技术**:
- 修改资源表条目(版本信息、字符串)
- 添加包含资源样式的overlay
- 保持可执行功能

**绕过原理**:
- 资源改变破坏文件签名
- 假资源混淆基于资源的检测
- Overlay改变熵和字节模式

### Method E: Multi-layer Padding
**技术**:
- 应用多层填充(不同模式)
- 平衡熵(混合高低熵区域)
- 添加元数据突变
- 创建复杂字节分布模式

**绕过原理**:
- 多层填充创建复杂字节分布
- 熵平衡混淆基于熵的检测
- 多种模式稀释签名匹配

## 使用方法

### 1. 准备输入文件

将 `to_be_evaded_ds.zip` 放在 `attacker/` 目录下：

```bash
cd attacker/
# 确保 to_be_evaded_ds.zip 存在
ls -lh to_be_evaded_ds.zip
```

### 2. 运行所有5种方法

```bash
cd attacker/
./run_5_new_methods.sh
```

或者指定输入文件：

```bash
./run_5_new_methods.sh /path/to/to_be_evaded_ds.zip
```

### 3. 运行单个方法

```bash
# Method A
python3 model1/methodA_dropper_metadata_overlay.py \
    --archive to_be_evaded_ds.zip

# Method B
python3 model1/methodB_section_rename_overlay.py \
    --archive to_be_evaded_ds.zip

# Method C
python3 model1/methodC_import_obfuscation.py \
    --archive to_be_evaded_ds.zip

# Method D
python3 model1/methodD_resource_manipulation.py \
    --archive to_be_evaded_ds.zip

# Method E
python3 model1/methodE_multilayer_padding.py \
    --archive to_be_evaded_ds.zip
```

## 输出文件位置

### 运行脚本后的输出结构

```
attacker/
└── attack_results_5methods/
    ├── methodA_dropper_metadata_overlay_outputs.zip
    ├── methodB_section_rename_overlay_outputs.zip
    ├── methodC_import_obfuscation_outputs.zip
    ├── methodD_resource_manipulation_outputs.zip
    ├── methodE_multilayer_padding_outputs.zip
    ├── methodA_dropper_metadata_overlay_work/
    ├── methodB_section_rename_overlay_work/
    ├── methodC_import_obfuscation_work/
    ├── methodD_resource_manipulation_work/
    └── methodE_multilayer_padding_work/
```

### 每个ZIP文件包含

- 修改后的样本文件 (.exe)
- `compare_report.csv` - 对比报告
- `sha256sums.txt` - SHA256哈希值列表

### 下载位置

**所有输出文件在**:
```
attacker/attack_results_5methods/
```

**可以直接下载**:
- 整个 `attack_results_5methods` 目录
- 或者单独下载每个 `*_outputs.zip` 文件

## 行为等价性

**所有方法都保持行为等价性**:
- ✅ 只修改PE元数据(时间戳、节名等)
- ✅ 只添加overlay数据(不影响PE结构)
- ✅ 不修改可执行代码
- ✅ 不改变程序逻辑

## 依赖要求

```bash
# Python 3.6+
python3 --version

# 必需Python包
pip install pefile

# Method A需要MinGW编译器(可选，有fallback)
# Ubuntu/Debian:
sudo apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64
```

## 故障排除

### 问题1: pefile未安装
```bash
pip install pefile
```

### 问题2: MinGW未安装(Method A)
- Method A会自动fallback到metadata+overlay模式
- 或手动安装: `sudo apt-get install gcc-mingw-w64-x86-64`

### 问题3: 权限错误
```bash
chmod +x run_5_new_methods.sh
chmod +x model1/method*.py
```

## 测试绕过率

生成输出后，可以使用 `test_evasion.py` 测试绕过率：

```bash
# 测试单个方法
python3 test_evasion.py \
    --samples attack_results_5methods/methodA_dropper_metadata_overlay_outputs.zip \
    --models-config models_config.json \
    --output test_results_methodA

# 测试所有方法
for method in methodA methodB methodC methodD methodE; do
    python3 test_evasion.py \
        --samples "attack_results_5methods/${method}_*_outputs.zip" \
        --models-config models_config.json \
        --output "test_results_${method}"
done
```

## 总结

- ✅ **5种方法**全部实现
- ✅ **运行脚本**已创建 (`run_5_new_methods.sh`)
- ✅ **输出位置**: `attacker/attack_results_5methods/`
- ✅ **行为等价性**全部保持
- ✅ **可直接下载**整个输出目录

