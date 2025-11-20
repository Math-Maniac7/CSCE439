#!/usr/bin/env python3
"""
Challenge测试脚本 - 测试模型在challenge数据集上的表现
"""

import argparse
import json
import pickle
import numpy as np
from pathlib import Path
import sys
import os
import zipfile
import tarfile
from tqdm import tqdm

# 导入模型类
defender_models_path = Path(__file__).parent.parent / 'defender' / 'defender' / 'models'
sys.path.insert(0, str(defender_models_path))
try:
    from ember_jsonl_model import EMBERJSONLModel
except ImportError:
    # 如果导入失败，尝试直接导入
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "ember_jsonl_model", 
        defender_models_path / "ember_jsonl_model.py"
    )
    ember_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ember_module)
    EMBERJSONLModel = ember_module.EMBERJSONLModel


def load_samples_from_path(sample_path):
    """从路径加载样本（支持目录、ZIP、TAR）"""
    samples = []
    path = Path(sample_path)
    
    if path.is_file():
        # 处理压缩文件
        if path.suffix == '.zip':
            with zipfile.ZipFile(path, 'r') as zf:
                temp_dir = path.parent / "temp_extract"
                temp_dir.mkdir(exist_ok=True)
                zf.extractall(temp_dir)
                samples = list(temp_dir.rglob("*.exe")) + list(temp_dir.rglob("*.dll"))
        elif path.suffix in ['.tar', '.gz', '.bz2']:
            with tarfile.open(path, 'r:*') as tf:
                temp_dir = path.parent / "temp_extract"
                temp_dir.mkdir(exist_ok=True)
                tf.extractall(temp_dir)
                samples = list(temp_dir.rglob("*.exe")) + list(temp_dir.rglob("*.dll"))
        else:
            # 单个文件
            samples = [path]
    elif path.is_dir():
        # 目录
        samples = list(path.rglob("*.exe")) + list(path.rglob("*.dll"))
    
    return samples


def test_model_on_samples(model, samples, label, max_samples=None):
    """在样本集上测试模型"""
    correct = 0
    total = 0
    errors = []
    predictions = []
    
    sample_list = samples[:max_samples] if max_samples else samples
    
    print(f"\n测试 {len(sample_list)} 个样本 (期望标签: {label})...")
    
    for sample_path in tqdm(sample_list, desc="测试进度"):
        try:
            with open(sample_path, 'rb') as f:
                bytez = f.read()
            
            # 预测
            prediction = model.predict(bytez)
            predictions.append(prediction)
            
            if prediction == label:
                correct += 1
            total += 1
            
        except Exception as e:
            errors.append((str(sample_path), str(e)))
            continue
    
    accuracy = correct / total if total > 0 else 0.0
    
    return {
        'total': total,
        'correct': correct,
        'accuracy': accuracy,
        'errors': errors,
        'predictions': predictions
    }


def test_model_challenge(model_path, challenge_dir, output_path=None):
    """测试模型在challenge数据集上"""
    print(f"\n{'='*60}")
    print(f"Challenge测试 - 模型: {model_path}")
    print(f"{'='*60}")
    
    # 加载模型
    print("加载模型...")
    model = EMBERJSONLModel(model_path=model_path, threshold=0.5)
    
    # 查找challenge目录中的goodware和malware
    challenge_path = Path(challenge_dir)
    
    # 查找goodware和malware目录/文件
    goodware_path = None
    malware_path = None
    
    # 可能的路径
    possible_goodware = [
        challenge_path / 'goodware',
        challenge_path / 'benign',
        challenge_path / 'goodware.zip',
        challenge_path / 'benign.zip',
    ]
    
    possible_malware = [
        challenge_path / 'malware',
        challenge_path / 'malicious',
        challenge_path / 'malware.zip',
        challenge_path / 'malicious.zip',
    ]
    
    for path in possible_goodware:
        if path.exists():
            goodware_path = path
            break
    
    for path in possible_malware:
        if path.exists():
            malware_path = path
            break
    
    if goodware_path is None:
        # 尝试查找所有子目录
        for subdir in challenge_path.iterdir():
            if subdir.is_dir():
                if 'good' in subdir.name.lower() or 'benign' in subdir.name.lower():
                    goodware_path = subdir
                elif 'mal' in subdir.name.lower() or 'evil' in subdir.name.lower():
                    malware_path = subdir
    
    if goodware_path is None or malware_path is None:
        raise ValueError(f"无法找到goodware或malware目录。\n"
                        f"Goodware路径: {goodware_path}\n"
                        f"Malware路径: {malware_path}\n"
                        f"请检查challenge目录结构: {challenge_dir}")
    
    print(f"Goodware路径: {goodware_path}")
    print(f"Malware路径: {malware_path}")
    
    # 加载样本
    print("\n加载样本...")
    goodware_samples = load_samples_from_path(goodware_path)
    malware_samples = load_samples_from_path(malware_path)
    
    print(f"Goodware样本数: {len(goodware_samples)}")
    print(f"Malware样本数: {len(malware_samples)}")
    
    # 测试goodware (期望标签: 0)
    print("\n" + "="*60)
    print("测试 Goodware (期望: 0)")
    print("="*60)
    goodware_results = test_model_on_samples(model, goodware_samples, label=0)
    
    # 测试malware (期望标签: 1)
    print("\n" + "="*60)
    print("测试 Malware (期望: 1)")
    print("="*60)
    malware_results = test_model_on_samples(model, malware_samples, label=1)
    
    # 汇总结果
    total_samples = goodware_results['total'] + malware_results['total']
    total_correct = goodware_results['correct'] + malware_results['correct']
    overall_accuracy = total_correct / total_samples if total_samples > 0 else 0.0
    
    # 计算FPR和TPR
    # FPR = FP / (FP + TN) = goodware中被误判为malware的比例
    fp = goodware_results['total'] - goodware_results['correct']  # goodware被误判为malware
    tn = goodware_results['correct']  # goodware正确识别为goodware
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    # TPR = TP / (TP + FN) = malware中被正确识别的比例
    tp = malware_results['correct']  # malware正确识别为malware
    fn = malware_results['total'] - malware_results['correct']  # malware被误判为goodware
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    results = {
        'model_path': str(model_path),
        'challenge_dir': str(challenge_dir),
        'goodware': {
            'total': goodware_results['total'],
            'correct': goodware_results['correct'],
            'accuracy': goodware_results['accuracy'],
            'errors': len(goodware_results['errors'])
        },
        'malware': {
            'total': malware_results['total'],
            'correct': malware_results['correct'],
            'accuracy': malware_results['accuracy'],
            'errors': len(malware_results['errors'])
        },
        'overall': {
            'total': total_samples,
            'correct': total_correct,
            'accuracy': overall_accuracy,
            'fpr': fpr,
            'tpr': tpr
        }
    }
    
    # 打印结果
    print("\n" + "="*60)
    print("测试结果汇总")
    print("="*60)
    print(f"Goodware:")
    print(f"  总数: {results['goodware']['total']}")
    print(f"  正确: {results['goodware']['correct']}")
    print(f"  准确率: {results['goodware']['accuracy']:.4f} ({results['goodware']['accuracy']*100:.2f}%)")
    print(f"\nMalware:")
    print(f"  总数: {results['malware']['total']}")
    print(f"  正确: {results['malware']['correct']}")
    print(f"  准确率: {results['malware']['accuracy']:.4f} ({results['malware']['accuracy']*100:.2f}%)")
    print(f"\n总体:")
    print(f"  总数: {results['overall']['total']}")
    print(f"  正确: {results['overall']['correct']}")
    print(f"  准确率: {results['overall']['accuracy']:.4f} ({results['overall']['accuracy']*100:.2f}%)")
    print(f"  假阳性率 (FPR): {results['overall']['fpr']:.4f} ({results['overall']['fpr']*100:.2f}%)")
    print(f"  真阳性率 (TPR): {results['overall']['tpr']:.4f} ({results['overall']['tpr']*100:.2f}%)")
    print("="*60)
    
    # 检查是否满足要求（至少有一个set达到100%）
    goodware_100 = results['goodware']['accuracy'] >= 1.0
    malware_100 = results['malware']['accuracy'] >= 1.0
    
    if goodware_100:
        print("✓ Goodware准确率达到100%!")
    if malware_100:
        print("✓ Malware准确率达到100%!")
    
    if not (goodware_100 or malware_100):
        print("⚠ 警告: 没有任何一个set达到100%准确率")
    
    # 保存结果
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n测试结果已保存: {output_path}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description='测试模型在challenge数据集上')
    parser.add_argument('--model-path', type=str, required=True,
                       help='模型文件路径')
    parser.add_argument('--challenge-dir', type=str, required=True,
                       help='Challenge数据集目录')
    parser.add_argument('--output', type=str, default=None,
                       help='测试结果输出文件路径')
    
    args = parser.parse_args()
    
    test_model_challenge(args.model_path, args.challenge_dir, args.output)


if __name__ == '__main__':
    main()

