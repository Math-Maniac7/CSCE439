#!/bin/bash
# 运行所有攻击方法并测试绕过率

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

INPUT_ARCHIVE="${1:-model1/to_be_evaded_ds.zip}"
OUTPUT_DIR="attack_results"
MODELS_CONFIG="${2:-models_config.json}"

echo "=== 运行所有攻击方法 ==="
echo "输入: $INPUT_ARCHIVE"
echo "输出目录: $OUTPUT_DIR"
echo "模型配置: $MODELS_CONFIG"

mkdir -p "$OUTPUT_DIR"

# 定义所有攻击方法
METHODS=(
    "method1_dropper"
    "method2_hybrid_overlay"
    "method3_safe_overlay"
    "method4_agent"
    "method5_llm_agent"
    "method6_feature_obfuscation"
    "method7_entropy_adjustment"
    "method8_hybrid_advanced"
)

# 运行每个攻击方法
for method in "${METHODS[@]}"; do
    echo ""
    echo "=========================================="
    echo "运行: $method"
    echo "=========================================="
    
    python3 "model1/${method}.py" \
        --archive "$INPUT_ARCHIVE" \
        --output "$OUTPUT_DIR/${method}_outputs.zip" \
        --work-dir "$OUTPUT_DIR/${method}_work"
    
    if [ -f "$OUTPUT_DIR/${method}_outputs.zip" ]; then
        echo "✓ $method 完成"
    else
        echo "✗ $method 失败"
    fi
done

echo ""
echo "=== 测试绕过率 ==="

# 测试每个方法的绕过率
for method in "${METHODS[@]}"; do
    if [ -f "$OUTPUT_DIR/${method}_outputs.zip" ]; then
        echo ""
        echo "测试 $method 的绕过率..."
        
        python3 test_evasion.py \
            --samples "$OUTPUT_DIR/${method}_outputs.zip" \
            --models-config "$MODELS_CONFIG" \
            --output "$OUTPUT_DIR/${method}_test_results" \
            --timeout 10 \
            --max-workers 10
    fi
done

echo ""
echo "=== 生成汇总报告 ==="

# 汇总所有结果
python3 << 'PYTHON_SCRIPT'
import json
import csv
from pathlib import Path
from collections import defaultdict

output_dir = Path("attack_results")
methods = [
    "method1_dropper", "method2_hybrid_overlay", "method3_safe_overlay",
    "method4_agent", "method5_llm_agent", "method6_feature_obfuscation",
    "method7_entropy_adjustment", "method8_hybrid_advanced"
]

summary = []
for method in methods:
    result_file = output_dir / f"{method}_test_results" / "evasion_report.json"
    if result_file.exists():
        with open(result_file) as f:
            data = json.load(f)
            for model_name, result in data.items():
                summary.append({
                    'method': method,
                    'model': model_name,
                    'bypass_rate': result['bypass_rate'],
                    'bypassed': result['bypassed'],
                    'total': result['total_samples']
                })

# 保存汇总
with open(output_dir / "summary_report.csv", 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['method', 'model', 'bypass_rate', 'bypassed', 'total'])
    writer.writeheader()
    writer.writerows(summary)

print("汇总报告已保存到: attack_results/summary_report.csv")
PYTHON_SCRIPT

echo ""
echo "=== 完成 ==="
echo "所有结果保存在: $OUTPUT_DIR"

