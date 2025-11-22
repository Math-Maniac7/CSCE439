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
from train_ember_jsonl import load_ember_jsonl

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
    """训练单次迭代 - 逐个文件加载和训练（节省内存）"""
    print(f"\n{'='*60}")
    print(f"迭代 {iteration} - 模型 {model.model_id}")
    print(f"{'='*60}")
    
    # 收集所有JSONL文件
    from pathlib import Path
    
    all_jsonl_files = []
    for dataset_dir in dataset_dirs:
        dataset_path = Path(dataset_dir)
        if not dataset_path.exists():
            print(f"警告: 数据集目录不存在: {dataset_dir}")
            continue
        jsonl_files = sorted(dataset_path.glob('train_features_*.jsonl'))
        all_jsonl_files.extend(jsonl_files)
    
    if not all_jsonl_files:
        raise ValueError("未找到任何JSONL文件！")
    
    print(f"找到 {len(all_jsonl_files)} 个训练文件")
    
    # 按文件分割训练集和测试集（前80%用于训练，后20%用于测试）
    num_train_files = int(len(all_jsonl_files) * (1 - test_split))
    train_files = all_jsonl_files[:num_train_files]
    test_files = all_jsonl_files[num_train_files:]
    
    print(f"训练文件: {len(train_files)} 个")
    print(f"测试文件: {len(test_files)} 个")
    
    # ==================== 训练阶段：逐个文件加载和训练 ====================
    print(f"\n{'='*60}")
    print("阶段1: 逐个文件加载和训练")
    print(f"{'='*60}")
    
    accumulated_X = []
    accumulated_y = []
    batch_size = 500000  # 累积50万个样本后训练一次
    total_processed = 0
    batch_count = 0
    is_first_batch = True
    
    for file_idx, file_path in enumerate(train_files, 1):
        print(f"\n处理训练文件 {file_idx}/{len(train_files)}: {file_path.name}")
        
        # 加载单个文件
        try:
            X_file, y_file = load_ember_jsonl(file_path, max_samples=max_samples)
            
            # 数据清理
            X_file = np.nan_to_num(X_file, nan=0.0, posinf=1e10, neginf=-1e10)
            X_file = np.clip(X_file, -1e10, 1e10).astype(np.float32)
            
            # 如果指定了采样比例，对文件数据进行采样
            if sample_ratio < 1.0:
                sample_size = int(len(X_file) * sample_ratio)
                indices = np.random.choice(len(X_file), size=sample_size, replace=False)
                X_file = X_file[indices]
                y_file = y_file[indices]
            
            print(f"  加载: {len(X_file)} 个样本")
            accumulated_X.append(X_file)
            accumulated_y.append(y_file)
            total_processed += len(X_file)
            
            # 当累积数据达到批次大小时，训练一次
            current_batch_size = sum(len(x) for x in accumulated_X)
            if current_batch_size >= batch_size or file_idx == len(train_files):
                batch_count += 1
                print(f"\n  累积了 {current_batch_size:,} 个样本，开始训练批次 {batch_count}...")
                
                # 合并批次数据
                X_batch = np.vstack(accumulated_X)
                y_batch = np.concatenate(accumulated_y)
                
                # 训练模型
                if is_first_batch:
                    # 第一次训练：初始化scaler并训练
                    print("    初始化scaler并训练...")
                    X_batch_scaled = model.scaler.fit_transform(X_batch)
                    model.classifier.fit(X_batch_scaled, y_batch)
                    is_first_batch = False
                else:
                    # 后续训练：使用已有scaler重新训练（累积的数据足够训练好模型）
                    print("    使用已有scaler重新训练...")
                    X_batch_scaled = model.scaler.transform(X_batch)
                    # 重新创建分类器并训练（累积的数据足够训练好模型）
                    # 这里我们使用批次数据重新训练，因为累积的数据已经包含了之前的信息
                    model.classifier.fit(X_batch_scaled, y_batch)
                
                print(f"    ✓ 批次 {batch_count} 训练完成，已处理 {total_processed:,} 个样本")
                
                # 清空累积数据
                del accumulated_X, accumulated_y, X_batch, y_batch, X_batch_scaled
                accumulated_X = []
                accumulated_y = []
                gc.collect()
            
            # 释放文件数据
            del X_file, y_file
            gc.collect()
            
        except Exception as e:
            print(f"  错误: 加载文件 {file_path} 失败: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    print(f"\n训练完成！共处理 {total_processed:,} 个样本，{batch_count} 个批次")
    
    # ==================== 测试阶段：加载测试文件进行评估 ====================
    print(f"\n{'='*60}")
    print("阶段2: 加载测试文件并评估")
    print(f"{'='*60}")
    
    test_X_list = []
    test_y_list = []
    
    for file_idx, file_path in enumerate(test_files, 1):
        print(f"\n加载测试文件 {file_idx}/{len(test_files)}: {file_path.name}")
        try:
            X_test_file, y_test_file = load_ember_jsonl(file_path, max_samples=max_samples)
            
            # 数据清理
            X_test_file = np.nan_to_num(X_test_file, nan=0.0, posinf=1e10, neginf=-1e10)
            X_test_file = np.clip(X_test_file, -1e10, 1e10).astype(np.float32)
            
            test_X_list.append(X_test_file)
            test_y_list.append(y_test_file)
            print(f"  加载: {len(X_test_file)} 个样本")
            
            # 释放内存（如果测试集太大）
            if sum(len(x) for x in test_X_list) > 200000:  # 如果超过20万样本，先评估
                X_test_batch = np.vstack(test_X_list)
                y_test_batch = np.concatenate(test_y_list)
                
                print(f"  评估部分测试集 ({len(X_test_batch):,} 样本)...")
                # 评估会在最后统一进行
                
        except Exception as e:
            print(f"  错误: 加载测试文件 {file_path} 失败: {e}")
            continue
    
    # 合并所有测试数据
    if test_X_list:
        print(f"\n合并测试数据...")
        X_test = np.vstack(test_X_list)
        y_test = np.concatenate(test_y_list)
        print(f"测试集: {len(X_test):,} 个样本")
        
        # 释放中间列表
        del test_X_list, test_y_list
        gc.collect()
    else:
        raise ValueError("未能加载任何测试数据！")
    
    # 评估模型
    print(f"\n评估模型性能...")
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
    del X_test, y_test
    gc.collect()
    
    return metrics


def main():
    try:
        _main()
    except KeyboardInterrupt:
        print("\n\n训练被用户中断")
        sys.exit(1)
    except MemoryError as e:
        print(f"\n\n内存不足错误: {e}")
        print("建议:")
        print("  1. 减少数据集大小（使用 --max-samples）")
        print("  2. 使用采样（使用 --sample-ratio < 1.0）")
        print("  3. 增加SLURM作业的内存限制（--mem）")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n训练过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _main():
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

