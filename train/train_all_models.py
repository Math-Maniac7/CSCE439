#!/usr/bin/env python3
"""
主训练脚本 - 训练所有5个模型，测试并选择最佳模型
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import os

import sys
from pathlib import Path
# 添加当前目录到路径
sys.path.insert(0, str(Path(__file__).parent))

from model_definitions import get_all_model_ids


def train_and_test_model(model_id, train_dir, test_dir, challenge_dir, 
                         output_dir, iterations, max_samples, sample_ratio, use_gpu):
    """训练单个模型并测试"""
    print(f"\n{'#'*80}")
    print(f"# 训练和测试模型: {model_id}")
    print(f"{'#'*80}\n")
    
    # 1. 训练模型
    print(f"步骤1: 训练模型 {model_id}...")
    train_cmd = [
        sys.executable, 
        str(Path(__file__).parent / 'train_iterative.py'),
        '--model-id', model_id,
        '--train-dir', train_dir,
        '--test-dir', test_dir,
        '--output-dir', str(Path(output_dir) / model_id),
        '--iterations', str(iterations),
        '--sample-ratio', str(sample_ratio),
    ]
    
    if max_samples:
        train_cmd.extend(['--max-samples', str(max_samples)])
    
    if use_gpu:
        train_cmd.append('--use-gpu')
    else:
        train_cmd.append('--no-gpu')
    
    print(f"执行命令: {' '.join(train_cmd)}")
    result = subprocess.run(train_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"训练失败: {result.stderr}")
        return None
    
    print(result.stdout)
    
    # 2. 测试模型
    model_path = Path(output_dir) / model_id / f"{model_id}_best.pickle"
    if not model_path.exists():
        print(f"错误: 模型文件不存在: {model_path}")
        return None
    
    print(f"\n步骤2: 测试模型 {model_id} 在challenge数据集上...")
    test_cmd = [
        sys.executable,
        str(Path(__file__).parent / 'test_challenge.py'),
        '--model-path', str(model_path),
        '--challenge-dir', challenge_dir,
        '--output', str(Path(output_dir) / model_id / f"{model_id}_challenge_results.json")
    ]
    
    print(f"执行命令: {' '.join(test_cmd)}")
    result = subprocess.run(test_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"测试失败: {result.stderr}")
        return None
    
    print(result.stdout)
    
    # 3. 读取测试结果
    results_path = Path(output_dir) / model_id / f"{model_id}_challenge_results.json"
    if results_path.exists():
        with open(results_path, 'r') as f:
            results = json.load(f)
        return results
    else:
        print(f"警告: 测试结果文件不存在: {results_path}")
        return None


def compare_models(all_results, output_dir):
    """比较所有模型并选择最佳模型"""
    print(f"\n{'#'*80}")
    print("# 模型比较和选择")
    print(f"{'#'*80}\n")
    
    if not all_results:
        print("没有可比较的模型结果")
        return None
    
    # 计算每个模型的得分
    model_scores = []
    for model_id, results in all_results.items():
        if results is None:
            continue
        
        overall = results.get('overall', {})
        goodware = results.get('goodware', {})
        malware = results.get('malware', {})
        
        # 得分计算：优先考虑TPR和FPR，同时考虑准确率
        # 目标: TPR >= 0.95, FPR <= 0.01
        tpr = overall.get('tpr', 0.0)
        fpr = overall.get('fpr', 1.0)
        accuracy = overall.get('accuracy', 0.0)
        
        # 检查是否满足100%要求
        goodware_100 = goodware.get('accuracy', 0.0) >= 1.0
        malware_100 = malware.get('accuracy', 0.0) >= 1.0
        
        # 综合得分
        score = (
            tpr * 0.4 +           # TPR权重
            (1.0 - fpr) * 0.3 +   # FPR权重（越小越好，所以用1-fpr）
            accuracy * 0.2 +       # 准确率权重
            (1.0 if goodware_100 or malware_100 else 0.0) * 0.1  # 100%奖励
        )
        
        model_scores.append({
            'model_id': model_id,
            'score': score,
            'tpr': tpr,
            'fpr': fpr,
            'accuracy': accuracy,
            'goodware_100': goodware_100,
            'malware_100': malware_100,
            'results': results
        })
    
    # 排序
    model_scores.sort(key=lambda x: x['score'], reverse=True)
    
    # 打印比较结果
    print("模型性能比较:")
    print(f"{'模型ID':<15} {'得分':<8} {'TPR':<8} {'FPR':<8} {'准确率':<8} {'Goodware 100%':<15} {'Malware 100%':<15}")
    print("-" * 90)
    
    for model in model_scores:
        print(f"{model['model_id']:<15} {model['score']:<8.4f} {model['tpr']:<8.4f} "
              f"{model['fpr']:<8.4f} {model['accuracy']:<8.4f} "
              f"{'✓' if model['goodware_100'] else '✗':<15} "
              f"{'✓' if model['malware_100'] else '✗':<15}")
    
    # 选择最佳模型
    if model_scores:
        best_model = model_scores[0]
        print(f"\n最佳模型: {best_model['model_id']}")
        print(f"  得分: {best_model['score']:.4f}")
        print(f"  TPR: {best_model['tpr']:.4f}")
        print(f"  FPR: {best_model['fpr']:.4f}")
        print(f"  准确率: {best_model['accuracy']:.4f}")
        
        # 复制最佳模型到最终位置
        best_model_path = Path(output_dir) / best_model['model_id'] / f"{best_model['model_id']}_best.pickle"
        final_model_path = Path(output_dir) / "best_model.pickle"
        
        if best_model_path.exists():
            import shutil
            shutil.copy2(best_model_path, final_model_path)
            print(f"\n最佳模型已复制到: {final_model_path}")
        
        # 保存比较结果
        comparison_path = Path(output_dir) / "model_comparison.json"
        with open(comparison_path, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'models': model_scores,
                'best_model': best_model['model_id']
            }, f, indent=2)
        print(f"比较结果已保存: {comparison_path}")
        
        return best_model
    
    return None


def main():
    parser = argparse.ArgumentParser(description='训练所有5个防御模型并选择最佳模型')
    parser.add_argument('--train-dir', type=str, required=True,
                       help='训练数据目录（EMBER数据集）')
    parser.add_argument('--test-dir', type=str, required=True,
                       help='测试数据目录（EMBER数据集）')
    parser.add_argument('--challenge-dir', type=str, required=True,
                       help='Challenge测试数据集目录')
    parser.add_argument('--output-dir', type=str, default='trained_models',
                       help='模型输出目录')
    parser.add_argument('--iterations', type=int, default=5,
                       help='每个模型的训练迭代次数')
    parser.add_argument('--max-samples', type=int, default=None,
                       help='每个文件最大样本数')
    parser.add_argument('--sample-ratio', type=float, default=1.0,
                       help='采样比例')
    parser.add_argument('--use-gpu', action='store_true', default=True,
                       help='使用GPU训练')
    parser.add_argument('--no-gpu', action='store_true',
                       help='禁用GPU')
    parser.add_argument('--models', type=str, nargs='+',
                       choices=['model1', 'model2', 'model3', 'model4', 'model5', 'all'],
                       default=['all'],
                       help='要训练的模型列表（默认: all）')
    
    args = parser.parse_args()
    
    use_gpu = args.use_gpu and not args.no_gpu
    
    # 确定要训练的模型
    if 'all' in args.models:
        model_ids = get_all_model_ids()
    else:
        model_ids = [m for m in args.models if m != 'all']
    
    print(f"将训练以下模型: {model_ids}")
    print(f"GPU使用: {'是' if use_gpu else '否'}")
    print(f"迭代次数: {args.iterations}")
    print(f"输出目录: {args.output_dir}")
    
    # 创建输出目录
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 训练和测试每个模型
    all_results = {}
    
    for model_id in model_ids:
        try:
            results = train_and_test_model(
                model_id=model_id,
                train_dir=args.train_dir,
                test_dir=args.test_dir,
                challenge_dir=args.challenge_dir,
                output_dir=str(output_dir),
                iterations=args.iterations,
                max_samples=args.max_samples,
                sample_ratio=args.sample_ratio,
                use_gpu=use_gpu
            )
            all_results[model_id] = results
        except Exception as e:
            print(f"处理模型 {model_id} 时出错: {e}")
            import traceback
            traceback.print_exc()
            all_results[model_id] = None
    
    # 比较模型并选择最佳
    best_model = compare_models(all_results, output_dir)
    
    print(f"\n{'#'*80}")
    print("# 训练完成")
    print(f"{'#'*80}")
    if best_model:
        print(f"最佳模型: {best_model['model_id']}")
        print(f"模型路径: {output_dir / 'best_model.pickle'}")
    else:
        print("未找到最佳模型")
    
    return 0 if best_model else 1


if __name__ == '__main__':
    sys.exit(main())

