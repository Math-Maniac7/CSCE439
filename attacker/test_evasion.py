#!/usr/bin/env python3
"""
测试攻击样本的绕过率

测试构造的攻击样本能绕过多少team的防御模型
"""

import argparse
import json
import requests
import time
import zipfile
from pathlib import Path
from collections import defaultdict
import csv
from tqdm import tqdm
import concurrent.futures
from typing import List, Tuple, Dict


class EvasionTester:
    """测试攻击样本绕过率"""
    
    def __init__(self, timeout: int = 10, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = defaultdict(dict)
    
    def test_single_sample(self, sample_path: Path, model_url: str, model_name: str) -> Tuple[bool, float, str]:
        """
        测试单个样本是否能绕过某个模型
        
        Returns:
            (bypassed, response_time, error_msg)
        """
        try:
            with open(sample_path, 'rb') as f:
                bytez = f.read()
            
            start_time = time.time()
            response = requests.post(
                model_url,
                data=bytez,
                headers={'Content-Type': 'application/octet-stream'},
                timeout=self.timeout
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    prediction = result.get('result', 1)  # 默认认为是恶意
                    # 如果预测为0（良性），说明绕过成功
                    bypassed = (prediction == 0)
                    return bypassed, elapsed, None
                except:
                    return False, elapsed, "Invalid JSON response"
            else:
                return False, elapsed, f"HTTP {response.status_code}"
                
        except requests.Timeout:
            # 超时算作绕过（根据挑战规则）
            return True, self.timeout, "Timeout"
        except Exception as e:
            return False, 0, str(e)
    
    def test_samples_against_model(self, samples: List[Path], model_url: str, model_name: str) -> Dict:
        """测试多个样本对某个模型的绕过率"""
        print(f"\n测试模型: {model_name}")
        print(f"URL: {model_url}")
        print(f"样本数: {len(samples)}")
        
        bypassed_count = 0
        total_time = 0
        errors = []
        results_detail = []
        
        # 使用线程池并行测试
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.test_single_sample, sample, model_url, model_name): sample
                for sample in samples
            }
            
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc=f"测试 {model_name}"):
                sample = futures[future]
                try:
                    bypassed, elapsed, error = future.result()
                    total_time += elapsed
                    
                    if bypassed:
                        bypassed_count += 1
                    
                    if error:
                        errors.append((sample.name, error))
                    
                    results_detail.append({
                        'sample': sample.name,
                        'bypassed': bypassed,
                        'time': elapsed,
                        'error': error
                    })
                except Exception as e:
                    errors.append((sample.name, str(e)))
        
        bypass_rate = bypassed_count / len(samples) if samples else 0
        
        result = {
            'model_name': model_name,
            'model_url': model_url,
            'total_samples': len(samples),
            'bypassed': bypassed_count,
            'bypass_rate': bypass_rate,
            'avg_time': total_time / len(samples) if samples else 0,
            'errors': len(errors),
            'error_details': errors[:10],  # 只保存前10个错误
            'details': results_detail
        }
        
        print(f"绕过率: {bypass_rate*100:.2f}% ({bypassed_count}/{len(samples)})")
        print(f"平均响应时间: {result['avg_time']:.3f}s")
        if errors:
            print(f"错误数: {len(errors)}")
        
        return result
    
    def test_against_all_models(self, samples: List[Path], model_configs: List[Dict]) -> Dict:
        """测试样本对所有模型的绕过率"""
        print(f"\n=== 开始测试 ===")
        print(f"样本数: {len(samples)}")
        print(f"模型数: {len(model_configs)}")
        
        all_results = {}
        
        for config in model_configs:
            model_name = config['name']
            model_url = config['url']
            
            result = self.test_samples_against_model(samples, model_url, model_name)
            all_results[model_name] = result
        
        return all_results
    
    def generate_report(self, results: Dict, output_path: Path):
        """生成测试报告"""
        print(f"\n=== 生成报告 ===")
        
        # 汇总统计
        summary = []
        for model_name, result in results.items():
            summary.append({
                'model': model_name,
                'url': result['model_url'],
                'total_samples': result['total_samples'],
                'bypassed': result['bypassed'],
                'bypass_rate': f"{result['bypass_rate']*100:.2f}%",
                'avg_time': f"{result['avg_time']:.3f}s",
                'errors': result['errors']
            })
        
        # 保存CSV报告
        csv_path = output_path / "evasion_report.csv"
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['model', 'url', 'total_samples', 'bypassed', 'bypass_rate', 'avg_time', 'errors'])
            writer.writeheader()
            writer.writerows(summary)
        
        # 保存详细JSON报告
        json_path = output_path / "evasion_report.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        # 打印汇总
        print("\n=== 绕过率汇总 ===")
        print(f"{'模型':<30} {'绕过数':<10} {'绕过率':<10} {'平均时间':<10}")
        print("-" * 70)
        for row in summary:
            print(f"{row['model']:<30} {row['bypassed']:<10} {row['bypass_rate']:<10} {row['avg_time']:<10}")
        
        print(f"\n报告已保存:")
        print(f"  CSV: {csv_path}")
        print(f"  JSON: {json_path}")


def load_samples_from_zip(zip_path: Path) -> List[Path]:
    """从ZIP文件加载样本"""
    samples = []
    with zipfile.ZipFile(zip_path, 'r') as zf:
        # 提取到临时目录
        temp_dir = zip_path.parent / "temp_extract"
        temp_dir.mkdir(exist_ok=True)
        zf.extractall(temp_dir)
        
        # 收集所有exe文件
        for path in temp_dir.rglob("*.exe"):
            samples.append(path)
    
    return samples


def load_samples_from_dir(dir_path: Path) -> List[Path]:
    """从目录加载样本"""
    samples = []
    for path in dir_path.rglob("*.exe"):
        samples.append(path)
    return samples


def load_model_configs(config_path: Path) -> List[Dict]:
    """从配置文件加载模型列表"""
    if not config_path.exists():
        # 返回默认配置（示例）
        return [
            {'name': 'Team1', 'url': 'http://localhost:8080/'},
            {'name': 'Team2', 'url': 'http://localhost:8081/'},
            {'name': 'Team3', 'url': 'http://localhost:8082/'},
        ]
    
    with open(config_path, 'r') as f:
        configs = json.load(f)
    
    return configs.get('models', [])


def main():
    parser = argparse.ArgumentParser(description='测试攻击样本的绕过率')
    parser.add_argument('--samples', type=Path, required=True,
                        help='攻击样本目录或ZIP文件')
    parser.add_argument('--models-config', type=Path, default=None,
                        help='模型配置文件（JSON格式）')
    parser.add_argument('--output', type=Path, default=Path('evasion_test_results'),
                        help='输出目录')
    parser.add_argument('--timeout', type=int, default=10,
                        help='请求超时时间（秒）')
    parser.add_argument('--max-workers', type=int, default=10,
                        help='并发线程数')
    parser.add_argument('--max-samples', type=int, default=None,
                        help='最大测试样本数（用于快速测试）')
    
    args = parser.parse_args()
    
    # 加载样本
    print("=== 加载样本 ===")
    if args.samples.suffix == '.zip':
        samples = load_samples_from_zip(args.samples)
    else:
        samples = load_samples_from_dir(args.samples)
    
    if args.max_samples:
        samples = samples[:args.max_samples]
    
    print(f"加载了 {len(samples)} 个样本")
    
    # 加载模型配置
    if args.models_config:
        model_configs = load_model_configs(args.models_config)
    else:
        # 使用默认配置或从环境变量读取
        model_configs = load_model_configs(Path('models_config.json'))
    
    print(f"配置了 {len(model_configs)} 个模型")
    
    # 创建输出目录
    args.output.mkdir(parents=True, exist_ok=True)
    
    # 运行测试
    tester = EvasionTester(timeout=args.timeout, max_workers=args.max_workers)
    results = tester.test_against_all_models(samples, model_configs)
    
    # 生成报告
    tester.generate_report(results, args.output)
    
    print("\n=== 测试完成 ===")


if __name__ == "__main__":
    main()

