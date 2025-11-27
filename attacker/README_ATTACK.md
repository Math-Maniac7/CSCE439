# 攻击方法说明

## 5种优化攻击方法

### Method A: Dropper + Metadata + Overlay (结合方法)
- **原理**: 结合Dropper、Metadata突变和Overlay三种技术
- **技术**:
  - Dropper: XOR加密 + Base64编码的payload嵌入C++ stub
  - Loader: 写入%TEMP%并通过CreateProcess执行
  - Metadata: TimeDateStamp随机化(2024-2025) + CheckSum=0
  - Overlay: ~1MB低熵良性overlay
  - 良性特征: Windows版本字符串、死代码路径、注册表查找
- **优点**: 综合多种技术，绕过率最高
- **适用**: 所有类型的检测模型

### Method B: Section Rename + Overlay (节表重命名)
- **原理**: 通过重命名PE节表来混淆检测模型
- **技术**:
  - 重命名节表 (.text → .code, .data → .info等)
  - 添加包含节表样式的良性overlay
  - 保持所有导入和功能
- **优点**: 保持行为完全不变，只修改元数据
- **适用**: 基于PE特征的检测模型

### Method C: Import Obfuscation (导入表混淆)
- **原理**: 通过混淆导入表来绕过基于导入的检测
- **技术**:
  - 添加良性导入字符串混淆检测
  - 修改导入表元数据(时间戳、版本信息)
  - 添加包含导入样式的大填充
- **优点**: 良性导入稀释恶意导入模式
- **适用**: 基于导入表的检测模型

### Method D: Resource Manipulation (资源表操作)
- **原理**: 通过操作资源表来混淆检测
- **技术**:
  - 修改资源表条目(版本信息、字符串)
  - 添加包含资源样式的overlay
  - 保持可执行功能
- **优点**: 资源改变破坏文件签名
- **适用**: 基于资源的检测模型

### Method E: Multi-layer Padding (多层填充)
- **原理**: 通过多层填充和熵平衡来绕过检测
- **技术**:
  - 应用多层填充(不同模式)
  - 平衡熵(混合高低熵区域)
  - 添加元数据突变
  - 创建复杂字节分布模式
- **优点**: 多层填充创建复杂字节分布，熵平衡混淆基于熵的检测
- **适用**: 基于熵值和字节分布的检测模型

## 使用方法

### 1. 运行单个攻击方法

```bash
# Method A: Dropper + Metadata + Overlay
python3 attacker/model1/methodA_dropper_metadata_overlay.py \
    --archive to_be_evaded_ds.zip

# Method B: Section Rename + Overlay
python3 attacker/model1/methodB_section_rename_overlay.py \
    --archive to_be_evaded_ds.zip

# Method C: Import Obfuscation
python3 attacker/model1/methodC_import_obfuscation.py \
    --archive to_be_evaded_ds.zip

# Method D: Resource Manipulation
python3 attacker/model1/methodD_resource_manipulation.py \
    --archive to_be_evaded_ds.zip

# Method E: Multi-layer Padding
python3 attacker/model1/methodE_multilayer_padding.py \
    --archive to_be_evaded_ds.zip
```

### 2. 运行所有5种方法（推荐）

```bash
# 使用专用脚本
cd attacker/
./run_5_new_methods.sh

# 或使用通用脚本
./run_all_attacks.sh to_be_evaded_ds.zip models_config.json
```

### 3. 测试绕过率

```bash
# 测试单个方法的绕过率
python3 attacker/test_evasion.py \
    --samples attack_results_5methods/methodA_dropper_metadata_overlay_outputs.zip \
    --models-config models_config.json \
    --output test_results

# 快速测试（限制样本数）
python3 attacker/test_evasion.py \
    --samples attack_results_5methods/methodA_dropper_metadata_overlay_outputs.zip \
    --models-config models_config.json \
    --output test_results \
    --max-samples 100
```

## 模型配置文件

创建 `models_config.json`:

```json
{
  "models": [
    {
      "name": "Team1_Defender",
      "url": "http://team1.example.com:8080/"
    },
    {
      "name": "Team2_Defender",
      "url": "http://team2.example.com:8080/"
    },
    {
      "name": "Local_Test",
      "url": "http://localhost:8080/"
    }
  ]
}
```

## 输出文件位置

运行后，所有输出文件保存在：

```
attacker/attack_results_5methods/
```

包含：
- `methodA_dropper_metadata_overlay_outputs.zip`
- `methodB_section_rename_overlay_outputs.zip`
- `methodC_import_obfuscation_outputs.zip`
- `methodD_resource_manipulation_outputs.zip`
- `methodE_multilayer_padding_outputs.zip`

每个ZIP文件包含：
- 修改后的样本文件
- `compare_report.csv` - 对比报告
- `sha256sums.txt` - SHA256哈希值列表

## 测试报告

测试完成后会生成：

1. **evasion_report.csv**: 汇总报告（CSV格式）
2. **evasion_report.json**: 详细报告（JSON格式）

报告包含：
- 每个模型的绕过率
- 每个样本的测试结果
- 平均响应时间
- 错误信息

## 行为等价性验证

**重要**: 所有攻击方法都设计为保持行为等价性：
- ✅ 只修改PE元数据（时间戳、节名等）
- ✅ 只添加overlay数据（不影响PE结构）
- ✅ 不修改可执行代码
- ✅ 不改变程序逻辑

建议在沙箱中验证行为等价性。

## 性能优化

- 使用 `--max-workers` 参数调整并发数
- 使用 `--timeout` 参数调整超时时间
- 使用 `--max-samples` 参数进行快速测试

## 注意事项

1. 确保所有防御模型的API可访问
2. 超时（timeout）会被计为绕过成功
3. 建议先用少量样本测试
4. 保存测试结果以便后续分析
5. Method A需要MinGW编译器（可选，有fallback）
