#!/bin/bash
# 运行5种新攻击方法的脚本
# 使用方法: ./run_5_new_methods.sh [输入zip文件路径]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 输入文件（默认在attacker目录下）
INPUT_ARCHIVE="${1:-to_be_evaded_ds.zip}"
OUTPUT_BASE_DIR="attack_results_5methods"

echo "=========================================="
echo "运行5种新攻击方法"
echo "=========================================="
echo "输入文件: $INPUT_ARCHIVE"
echo "输出目录: $OUTPUT_BASE_DIR"
echo ""

# 检查输入文件
if [ ! -f "$INPUT_ARCHIVE" ]; then
    echo "错误: 输入文件不存在: $INPUT_ARCHIVE"
    echo "请将 to_be_evaded_ds.zip 放在 attacker/ 目录下"
    exit 1
fi

mkdir -p "$OUTPUT_BASE_DIR"

# 定义5种方法
METHODS=(
    "methodA_dropper_metadata_overlay"
    "methodB_section_rename_overlay"
    "methodC_import_obfuscation"
    "methodD_resource_manipulation"
    "methodE_multilayer_padding"
)

METHOD_NAMES=(
    "Method A: Dropper + Metadata + Overlay"
    "Method B: Section Rename + Overlay"
    "Method C: Import Obfuscation"
    "Method D: Resource Manipulation"
    "Method E: Multi-layer Padding"
)

# 运行每个方法
for i in "${!METHODS[@]}"; do
    method="${METHODS[$i]}"
    method_name="${METHOD_NAMES[$i]}"
    
    echo ""
    echo "=========================================="
    echo "[$((i+1))/5] $method_name"
    echo "=========================================="
    
    python3 "model1/${method}.py" \
        --archive "$INPUT_ARCHIVE" \
        --work-root "$OUTPUT_BASE_DIR/${method}_work" \
        --output-zip "$OUTPUT_BASE_DIR/${method}_outputs.zip"
    
    if [ -f "$OUTPUT_BASE_DIR/${method}_outputs.zip" ]; then
        size=$(du -h "$OUTPUT_BASE_DIR/${method}_outputs.zip" | cut -f1)
        echo "✓ $method_name 完成 (大小: $size)"
    else
        echo "✗ $method_name 失败"
    fi
done

echo ""
echo "=========================================="
echo "所有方法运行完成！"
echo "=========================================="
echo ""
echo "输出文件位置:"
echo "  目录: $OUTPUT_BASE_DIR/"
echo ""
echo "生成的ZIP文件:"
for method in "${METHODS[@]}"; do
    if [ -f "$OUTPUT_BASE_DIR/${method}_outputs.zip" ]; then
        size=$(du -h "$OUTPUT_BASE_DIR/${method}_outputs.zip" | cut -f1)
        echo "  - $OUTPUT_BASE_DIR/${method}_outputs.zip ($size)"
    fi
done
echo ""
echo "下载位置:"
echo "  所有输出文件在: $(pwd)/$OUTPUT_BASE_DIR/"
echo "  可以直接下载整个 $OUTPUT_BASE_DIR 目录"
echo ""

