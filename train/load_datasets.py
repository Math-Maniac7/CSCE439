#!/usr/bin/env python3
"""
从多个EMBER数据集目录加载数据并自动切分
"""

import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from train_ember_jsonl import load_ember_jsonl, load_multiple_jsonl_files


def load_all_ember_datasets(dataset_dirs, max_samples_per_file=None, test_split=0.2, random_state=42):
    """
    从多个EMBER数据集目录加载所有数据，合并后切分为训练集和测试集
    
    Args:
        dataset_dirs: 数据集目录列表（例如：['/path/to/ember2017_2', '/path/to/ember2018_2', '/path/to/ember']）
        max_samples_per_file: 每个文件最大加载样本数（None表示加载全部）
        test_split: 测试集比例（默认0.2，即20%）
        random_state: 随机种子
    
    Returns:
        X_train, X_test, y_train, y_test: 切分后的训练集和测试集
    """
    print(f"\n{'='*60}")
    print("加载所有EMBER数据集")
    print(f"{'='*60}\n")
    
    all_jsonl_files = []
    
    # 收集所有数据集目录中的JSONL文件
    for dataset_dir in dataset_dirs:
        dataset_path = Path(dataset_dir)
        if not dataset_path.exists():
            print(f"警告: 数据集目录不存在: {dataset_dir}")
            continue
        
        # 查找所有train_features_*.jsonl文件
        jsonl_files = sorted(dataset_path.glob('train_features_*.jsonl'))
        if jsonl_files:
            print(f"在 {dataset_dir} 中找到 {len(jsonl_files)} 个训练文件")
            all_jsonl_files.extend(jsonl_files)
        else:
            print(f"警告: 在 {dataset_dir} 中未找到train_features_*.jsonl文件")
    
    if not all_jsonl_files:
        raise ValueError("未找到任何JSONL文件！请检查数据集目录路径。")
    
    print(f"\n总共找到 {len(all_jsonl_files)} 个JSONL文件")
    print("文件列表:")
    for i, f in enumerate(all_jsonl_files, 1):
        print(f"  {i}. {f}")
    
    # 加载所有文件并合并
    print(f"\n开始加载数据...")
    X_all, y_all = load_multiple_jsonl_files(
        all_jsonl_files,
        max_samples_per_file=max_samples_per_file
    )
    
    print(f"\n合并后总数据量: {len(X_all)} 个样本")
    print(f"标签分布: {np.sum(y_all == 1)} 恶意, {np.sum(y_all == 0)} 良性")
    
    # 切分为训练集和测试集（80/20）
    print(f"\n切分数据集: {int((1-test_split)*100)}% 训练集, {int(test_split*100)}% 测试集")
    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y_all,
        test_size=test_split,
        random_state=random_state,
        stratify=y_all  # 保持标签分布
    )
    
    print(f"训练集: {len(X_train)} 个样本")
    print(f"  恶意: {np.sum(y_train == 1)}, 良性: {np.sum(y_train == 0)}")
    print(f"测试集: {len(X_test)} 个样本")
    print(f"  恶意: {np.sum(y_test == 1)}, 良性: {np.sum(y_test == 0)}")
    
    return X_train, X_test, y_train, y_test

