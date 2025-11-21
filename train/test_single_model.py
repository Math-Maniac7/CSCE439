#!/usr/bin/env python3
"""
快速测试单个模型 - 本地测试用
"""

import sys
from pathlib import Path

# 添加当前目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from model_definitions import create_model
from load_datasets import load_all_ember_datasets
from train_iterative import evaluate_model
import argparse


def main():
    parser = argparse.ArgumentParser(description='快速测试单个模型')
    parser.add_argument('--model-id', type=str, default='model1',
                       choices=['model1', 'model2', 'model3', 'model4', 'model5'],
                       help='模型ID')
    parser.add_argument('--dataset-dir', type=str, action='append', required=True,
                       help='数据集目录')
    parser.add_argument('--max-samples', type=int, default=1000,
                       help='最大样本数（测试用）')
    parser.add_argument('--test-split', type=float, default=0.2,
                       help='测试集比例')
    
    args = parser.parse_args()
    
    print("="*60)
    print(f"测试模型: {args.model_id}")
    print("="*60)
    
    # 创建模型
    print("\n1. 创建模型...")
    model = create_model(args.model_id, use_gpu=False)
    print(f"   模型类型: {type(model.classifier).__name__}")
    
    # 加载数据
    print("\n2. 加载数据（小样本测试）...")
    try:
        X_train, X_test, y_train, y_test = load_all_ember_datasets(
            dataset_dirs=args.dataset_dir,
            max_samples_per_file=args.max_samples,
            test_split=args.test_split,
            random_state=42
        )
        print(f"   训练集: {len(X_train)} 样本")
        print(f"   测试集: {len(X_test)} 样本")
    except Exception as e:
        print(f"   ❌ 数据加载失败: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # 训练模型
    print("\n3. 训练模型...")
    try:
        model.fit(X_train, y_train)
        print("   ✓ 训练完成")
    except Exception as e:
        print(f"   ❌ 训练失败: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # 评估模型
    print("\n4. 评估模型...")
    try:
        metrics = evaluate_model(model, X_test, y_test)
        print("\n   测试结果:")
        print(f"   准确率: {metrics['accuracy']:.4f}")
        print(f"   TPR: {metrics['tpr']:.4f}")
        print(f"   FPR: {metrics['fpr']:.4f}")
        print(f"   F1: {metrics['f1']:.4f}")
    except Exception as e:
        print(f"   ❌ 评估失败: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    print("\n" + "="*60)
    print("✓ 测试成功！代码可以正常运行")
    print("="*60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

