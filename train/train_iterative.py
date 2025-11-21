#!/usr/bin/env python3
"""
迭代训练脚本 - 多次训练并保存最佳模型
"""

import json
import pickle
import numpy as np
import argparse
import gc
from pathlib import Path
from tqdm import tqdm
import sys
import os

# 导入模型定义和数据加载函数
import sys
from pathlib import Path
# 添加当前目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from model_definitions import create_model, get_all_model_ids
from load_datasets import load_all_ember_datasets

from sklearn.metrics import (
    accuracy_score, f1_score, recall_score, precision_score, 
    confusion_matrix, roc_auc_score
)


def evaluate_model(model, X_test, y_test):
    """评估模型性能"""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    try:
        auc = roc_auc_score(y_test, y_proba)
    except:
        auc = 0.0
    
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    
    # 计算FPR和TPR
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'auc': auc,
        'fpr': fpr,
        'tpr': tpr,
        'tn': int(tn),
        'fp': int(fp),
        'fn': int(fn),
        'tp': int(tp)
    }


def train_single_iteration(model, dataset_dirs, iteration, max_samples=None, sample_ratio=1.0, test_split=0.2):
    """训练单次迭代"""
    print(f"\n{'='*60}")
    print(f"迭代 {iteration} - 模型 {model.model_id}")
    print(f"{'='*60}")
    
    # 加载所有数据集并自动切分
    print("加载所有数据集并切分...")
    X_train, X_test, y_train, y_test = load_all_ember_datasets(
        dataset_dirs=dataset_dirs,
        max_samples_per_file=max_samples,
        test_split=test_split,
        random_state=42 + iteration  # 每次迭代使用不同的随机种子
    )
    
    # 如果指定了采样比例，对训练集进行采样
    if sample_ratio < 1.0:
        import numpy as np
        sample_size = int(len(X_train) * sample_ratio)
        indices = np.random.choice(len(X_train), size=sample_size, replace=False)
        X_train = X_train[indices]
        y_train = y_train[indices]
        print(f"采样后训练集: {len(X_train)} 个样本")
    
    # 数据清理：处理无穷大值和NaN
    print("清理数据（处理inf和NaN）...")
    import numpy as np
    
    # 统计异常值
    inf_count = np.isinf(X_train).sum()
    nan_count = np.isnan(X_train).sum()
    
    if inf_count > 0 or nan_count > 0:
        print(f"  发现 {inf_count} 个inf值, {nan_count} 个NaN值，正在清理...")
    
    # 替换无穷大值为有限值
    # 使用非常小的负数和非常大的正数来替换-inf和+inf
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=1e10, neginf=-1e10)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=1e10, neginf=-1e10)
    
    # 进一步限制数值范围到float32安全范围
    # float32范围: -3.4e38 到 3.4e38
    # 但我们使用更保守的范围以避免训练问题
    max_val = 1e10
    min_val = -1e10
    X_train = np.clip(X_train, min_val, max_val).astype(np.float32)
    X_test = np.clip(X_test, min_val, max_val).astype(np.float32)
    
    print(f"  数据清理完成，训练集形状: {X_train.shape}, 测试集形状: {X_test.shape}")
    print(f"  数值范围: [{X_train.min():.2e}, {X_train.max():.2e}]")
    
    # 训练模型
    print("开始训练...")
    model.fit(X_train, y_train)
    
    # 评估模型
    print("评估模型性能...")
    metrics = evaluate_model(model, X_test, y_test)
    
    print(f"\n测试集性能:")
    print(f"  准确率 (Accuracy): {metrics['accuracy']:.4f}")
    print(f"  精确率 (Precision): {metrics['precision']:.4f}")
    print(f"  召回率 (Recall/TPR): {metrics['recall']:.4f}")
    print(f"  F1分数: {metrics['f1']:.4f}")
    print(f"  AUC: {metrics['auc']:.4f}")
    print(f"  假阳性率 (FPR): {metrics['fpr']:.4f}")
    print(f"  真阳性率 (TPR): {metrics['tpr']:.4f}")
    print(f"  混淆矩阵: TN={metrics['tn']}, FP={metrics['fp']}, FN={metrics['fn']}, TP={metrics['tp']}")
    
    # 清理内存
    del X_train, y_train
    gc.collect()
    
    return metrics


def main():
    parser = argparse.ArgumentParser(description='迭代训练防御模型')
    parser.add_argument('--model-id', type=str, required=True,
                       choices=['model1', 'model2', 'model3', 'model4', 'model5'],
                       help='模型ID')
    parser.add_argument('--dataset-dir', type=str, action='append', required=True,
                       help='EMBER数据集目录（可指定多个，例如：--dataset-dir dir1 --dataset-dir dir2）')
    parser.add_argument('--output-dir', type=str, default='models',
                       help='模型输出目录')
    parser.add_argument('--iterations', type=int, default=5,
                       help='训练迭代次数')
    parser.add_argument('--max-samples', type=int, default=None,
                       help='每个文件最大样本数')
    parser.add_argument('--sample-ratio', type=float, default=1.0,
                       help='采样比例（对训练集的采样，不影响测试集）')
    parser.add_argument('--test-split', type=float, default=0.2,
                       help='测试集比例（默认0.2，即20%），剩余80%作为训练集')
    parser.add_argument('--use-gpu', action='store_true', default=True,
                       help='使用GPU训练')
    parser.add_argument('--no-gpu', action='store_true',
                       help='禁用GPU')
    
    args = parser.parse_args()
    
    use_gpu = args.use_gpu and not args.no_gpu
    
    # 创建输出目录
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 创建模型
    model = create_model(args.model_id, use_gpu=use_gpu)
    
    # 存储所有迭代的结果
    all_metrics = []
    best_metrics = None
    best_iteration = -1
    best_model = None
    
    # 多次迭代训练
    for iteration in range(1, args.iterations + 1):
        # 创建新的模型实例（每次迭代使用新的随机种子）
        # 注意：模型类内部已经设置了不同的random_state，所以每次创建都会不同
        model = create_model(args.model_id, use_gpu=use_gpu)
        
        # 训练并评估
        try:
            metrics = train_single_iteration(
                model, 
                args.dataset_dir,
                iteration,
                max_samples=args.max_samples,
                sample_ratio=args.sample_ratio,
                test_split=args.test_split
            )
        except Exception as e:
            print(f"迭代 {iteration} 训练失败: {e}")
            import traceback
            traceback.print_exc()
            continue
        
        metrics['iteration'] = iteration
        all_metrics.append(metrics)
        
        # 判断是否是最佳模型（优先考虑TPR和FPR）
        # 目标: TPR >= 0.95, FPR <= 0.01
        is_better = False
        if best_metrics is None:
            is_better = True
        else:
            # 计算综合得分：TPR权重高，FPR权重高（越小越好）
            current_score = metrics['tpr'] * 0.6 - metrics['fpr'] * 0.4 + metrics['accuracy'] * 0.2
            best_score = best_metrics['tpr'] * 0.6 - best_metrics['fpr'] * 0.4 + best_metrics['accuracy'] * 0.2
            
            if current_score > best_score:
                is_better = True
        
        if is_better:
            best_metrics = metrics.copy()
            best_iteration = iteration
            best_model = model
            print(f"\n✓ 发现更好的模型 (迭代 {iteration})")
            print(f"  得分: {metrics['tpr'] * 0.6 - metrics['fpr'] * 0.4 + metrics['accuracy'] * 0.2:.4f}")
    
    # 保存最佳模型
    if best_model is not None:
        model_path = output_dir / f"{args.model_id}_best.pickle"
        best_model.save(str(model_path))
        print(f"\n{'='*60}")
        print(f"最佳模型已保存: {model_path}")
        print(f"最佳迭代: {best_iteration}")
        print(f"最佳性能: TPR={best_metrics['tpr']:.4f}, FPR={best_metrics['fpr']:.4f}, Accuracy={best_metrics['accuracy']:.4f}")
        print(f"{'='*60}")
    
    # 保存所有迭代的结果
    results_path = output_dir / f"{args.model_id}_training_results.json"
    with open(results_path, 'w') as f:
        json.dump({
            'model_id': args.model_id,
            'iterations': all_metrics,
            'best_iteration': best_iteration,
            'best_metrics': best_metrics
        }, f, indent=2)
    print(f"\n训练结果已保存: {results_path}")
    
    return best_model, best_metrics


if __name__ == '__main__':
    main()

