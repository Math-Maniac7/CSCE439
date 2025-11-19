# 攻击方法说明

## 新增攻击方法

### Method 6: Feature Obfuscation (特征混淆)
- **原理**: 通过修改PE文件特征来混淆检测模型
- **技术**:
  - 修改PE头字段（时间戳、版本信息）
  - 重命名节表（.text -> .code等）
  - 添加良性导入库字符串
  - 添加良性overlay数据
- **优点**: 保持行为完全不变，只修改元数据
- **适用**: 基于PE特征的检测模型

### Method 7: Entropy Adjustment (熵值调整)
- **原理**: 通过调整文件熵值来绕过基于熵的检测
- **技术**:
  - 添加重复模式降低高熵
  - 添加随机数据提高低熵
  - 平衡字节分布
- **优点**: 针对熵值特征有效
- **适用**: 基于熵值特征的检测模型

### Method 8: Advanced Hybrid (高级混合)
- **原理**: 结合多种技术的混合攻击
- **技术**:
  - PE头混淆
  - 熵值调整
  - 多层良性overlay
  - 时间戳伪造
- **优点**: 综合多种技术，绕过率更高
- **适用**: 多种检测模型的组合

## 使用方法

### 1. 运行单个攻击方法

```bash
# Method 6: 特征混淆
python3 attacker/model1/method6_feature_obfuscation.py \
    --archive to_be_evaded_ds.zip \
    --output method6_outputs.zip

# Method 7: 熵值调整
python3 attacker/model1/method7_entropy_adjustment.py \
    --archive to_be_evaded_ds.zip \
    --output method7_outputs.zip

# Method 8: 高级混合
python3 attacker/model1/method8_hybrid_advanced.py \
    --archive to_be_evaded_ds.zip \
    --output method8_outputs.zip
```

### 2. 测试绕过率

```bash
# 测试单个方法的绕过率
python3 attacker/test_evasion.py \
    --samples method6_outputs.zip \
    --models-config models_config.json \
    --output test_results

# 快速测试（限制样本数）
python3 attacker/test_evasion.py \
    --samples method6_outputs.zip \
    --models-config models_config.json \
    --output test_results \
    --max-samples 100
```

### 3. 运行所有攻击方法并测试

```bash
# 运行所有方法并自动测试
./attacker/run_all_attacks.sh to_be_evaded_ds.zip models_config.json
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
- 只修改PE元数据（时间戳、节名等）
- 只添加overlay数据（不影响PE结构）
- 不修改可执行代码
- 不改变程序逻辑

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

