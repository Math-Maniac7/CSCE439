# 快速开始指南

## 🎯 老师推荐的方法

**Method A: Dropper + Metadata + Overlay** 是老师推荐的方法！

这是结合了两种技术的优化方法：
1. **Dropper技术** (来自method1)
2. **Metadata + Overlay技术** (来自method3)

## ✅ 行为等价性确认

**Method A 完全保留原始EXE的运行结果**：

1. **Dropper机制**：
   - 将原始PE文件进行XOR加密 + Base64编码
   - 嵌入到C++ stub中
   - **关键**：Loader将原始PE文件**完整写入%TEMP%**
   - 使用 `CreateProcessA` **执行原始PE文件**
   - **结果**：执行的是完全相同的原始程序，行为100%一致

2. **Metadata修改**：
   - 只修改 `TimeDateStamp` 和 `CheckSum`
   - 这些字段**Windows会忽略**，不影响执行

3. **Overlay添加**：
   - 在文件末尾添加overlay数据
   - **不影响PE结构**，Windows加载器会忽略

**验证**：代码第205行 `CreateProcessA(path, ...)` 执行的是写入%TEMP%的**原始PE文件**，不是修改后的版本。

## 🚀 运行命令

### 方法1: 运行所有5种方法（推荐）

```bash
cd attacker/
./run_5_new_methods.sh
```

### 方法2: 只运行老师推荐的Method A

```bash
cd attacker/
python3 model1/methodA_dropper_metadata_overlay.py \
    --archive to_be_evaded_ds.zip
```

### 方法3: 指定输入文件路径

```bash
cd attacker/
python3 model1/methodA_dropper_metadata_overlay.py \
    --archive /path/to/to_be_evaded_ds.zip \
    --output-zip methodA_outputs.zip
```

## 📁 输出文件位置

运行后，输出文件在：

```
attacker/attack_results_5methods/
```

或者如果单独运行Method A：

```
attacker/model1/methodA_dropper_metadata_overlay_outputs.zip
```

每个ZIP文件包含：
- ✅ 修改后的样本文件（.exe）
- ✅ `compare_report.csv` - 对比报告
- ✅ `sha256sums.txt` - SHA256哈希值

## 🔍 验证行为等价性

### 在Windows上验证：

1. **运行原始EXE**：
   ```cmd
   original.exe
   ```

2. **运行Method A生成的EXE**：
   ```cmd
   methodA_output.exe
   ```

3. **对比结果**：
   - 两个程序应该产生**完全相同的行为**
   - 进程树应该相同
   - 文件操作、网络连接等应该一致

### 使用沙箱验证（推荐）：

- 上传到 [Any.Run](https://any.run) 或类似沙箱
- 对比原始样本和Method A生成的样本
- 验证进程树、行为完全一致

## 📊 5种方法对比

| 方法 | 老师推荐 | 行为等价 | 技术特点 |
|------|---------|---------|---------|
| **Method A** | ✅ **是** | ✅ **完全保留** | Dropper + Metadata + Overlay |
| Method B | ❌ | ✅ 保留 | Section Rename + Overlay |
| Method C | ❌ | ✅ 保留 | Import Obfuscation |
| Method D | ❌ | ✅ 保留 | Resource Manipulation |
| Method E | ❌ | ✅ 保留 | Multi-layer Padding |

## ⚠️ 注意事项

1. **Method A需要MinGW编译器**（可选）：
   - 如果没有MinGW，会自动fallback到metadata+overlay模式
   - 安装：`sudo apt-get install gcc-mingw-w64-x86-64`

2. **输入文件**：
   - 确保 `to_be_evaded_ds.zip` 在 `attacker/` 目录下
   - 或使用 `--archive` 参数指定路径

3. **输出大小**：
   - Method A生成的dropper大约1.2MB
   - 加上overlay后可能达到2-3MB

## 🎓 总结

- **运行命令**：`./run_5_new_methods.sh` 或单独运行Method A
- **老师推荐**：**Method A** (methodA_dropper_metadata_overlay.py)
- **行为等价性**：✅ **完全保留**，因为执行的是原始PE文件
- **输出位置**：`attacker/attack_results_5methods/` 或 `attacker/model1/`

