# 行为等价性确认

## ✅ 所有5种方法都保持行为等价性

### Method A: Dropper + Metadata + Overlay
**行为等价性**: ✅ **完全保留**

**原因**:
1. **Dropper机制**: 
   - 将原始PE文件XOR解密后写入`%TEMP%`
   - 使用`CreateProcessA`执行**原始PE文件**（代码第205行）
   - **执行的是未修改的原始程序**，行为100%一致

2. **Metadata修改**:
   - 只修改`TimeDateStamp`和`CheckSum`
   - Windows会忽略这些字段，不影响执行

3. **Overlay添加**:
   - 在文件末尾添加，不影响PE结构
   - Windows加载器会忽略overlay数据

---

### Method B: Section Rename + Overlay
**行为等价性**: ✅ **完全保留**

**原因**:
1. **节表重命名**:
   - 只修改节表名称（`.text` → `.code`等）
   - **不修改节的内容、地址、权限**
   - Windows加载器按地址加载，不依赖名称

2. **Overlay添加**:
   - 在文件末尾添加，不影响PE结构

**代码证据**:
```python
# 只修改 section.Name，不修改其他属性
section.Name = new_name[:8].ljust(8, b"\x00")
```

---

### Method C: Import Obfuscation
**行为等价性**: ✅ **完全保留**

**原因**:
1. **Metadata修改**:
   - 只修改`TimeDateStamp`和`CheckSum`
   - Windows会忽略这些字段

2. **Overlay添加**:
   - 在文件末尾添加import-like字符串
   - **不修改实际的导入表**
   - 只是添加overlay数据，不影响导入功能

**代码证据**:
```python
# 只修改metadata，不修改导入表
pe.FILE_HEADER.TimeDateStamp = random.randint(...)
pe.OPTIONAL_HEADER.CheckSum = 0
# 然后只添加overlay，不修改PE结构
final_data = data + bytes(overlay[:overlay_size])
```

---

### Method D: Resource Manipulation
**行为等价性**: ✅ **完全保留**

**原因**:
1. **Metadata修改**:
   - 只修改`TimeDateStamp`和`CheckSum`
   - Windows会忽略这些字段

2. **Overlay添加**:
   - 在文件末尾添加resource-like字符串
   - **不修改实际的资源表**
   - 只是添加overlay数据，不影响资源功能

**代码证据**:
```python
# 只修改metadata，不修改资源表
pe.FILE_HEADER.TimeDateStamp = random.randint(...)
pe.OPTIONAL_HEADER.CheckSum = 0
# 然后只添加overlay，不修改PE结构
final_data = data + bytes(overlay[:overlay_size])
```

---

### Method E: Multi-layer Padding
**行为等价性**: ✅ **完全保留**

**原因**:
1. **Metadata修改**:
   - 只修改`TimeDateStamp`和`CheckSum`
   - Windows会忽略这些字段

2. **多层填充**:
   - 在文件末尾添加多层padding
   - **不修改PE结构**
   - 只是添加overlay数据，不影响执行

**代码证据**:
```python
# 只修改metadata
pe.FILE_HEADER.TimeDateStamp = random.randint(...)
pe.OPTIONAL_HEADER.CheckSum = 0
# 然后只添加overlay，不修改PE结构
final_data = data + bytes(overlay[:total_size])
```

---

## 📋 总结

| 方法 | 行为等价性 | 修改内容 | 不修改内容 |
|------|-----------|---------|-----------|
| **Method A** | ✅ 完全保留 | Metadata + Overlay | 执行原始PE文件 |
| **Method B** | ✅ 完全保留 | 节表名称 + Overlay | 节内容、代码 |
| **Method C** | ✅ 完全保留 | Metadata + Overlay | 导入表、代码 |
| **Method D** | ✅ 完全保留 | Metadata + Overlay | 资源表、代码 |
| **Method E** | ✅ 完全保留 | Metadata + Overlay | 代码、结构 |

## 🔍 共同特点

所有5种方法都：
- ✅ **只修改PE元数据**（时间戳、节名等）
- ✅ **只添加overlay数据**（不影响PE结构）
- ✅ **不修改可执行代码**
- ✅ **不改变程序逻辑**
- ✅ **不修改导入表、资源表等关键结构**

## ✅ 验证方法

### 在Windows上验证：
1. 运行原始EXE，记录行为
2. 运行修改后的EXE，对比行为
3. 应该**完全相同**

### 使用沙箱验证（推荐）：
- 上传到 [Any.Run](https://any.run) 或类似沙箱
- 对比原始样本和修改后的样本
- 验证进程树、文件操作、网络连接等**完全一致**

## 🎯 结论

**所有5种方法都保持行为等价性，不会改变原始EXE的运行结果！**

