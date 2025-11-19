#!/usr/bin/env python3
"""
训练基于EMBER JSONL数据集的恶意软件检测模型

该脚本从JSONL格式的EMBER数据集中加载特征，训练一个机器学习模型，
并保存为pickle文件供部署使用。
"""

import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score, confusion_matrix
import argparse
import gc
from tqdm import tqdm


class EMBERModel:
    """基于EMBER特征的恶意软件检测模型"""
    
    def __init__(self, 
                 classifier=RandomForestClassifier(
                     n_estimators=100,
                     max_depth=30,
                     max_features='sqrt',
                     n_jobs=-1,
                     random_state=42,
                     verbose=1
                 )):
        self.classifier = classifier
        self.scaler = MinMaxScaler()
        self.feature_names = None
        
    def fit(self, X, y):
        """训练模型"""
        print("正在训练特征缩放器...")
        X_scaled = self.scaler.fit_transform(X)
        
        print("正在训练分类器...")
        self.classifier.fit(X_scaled, y)
    
    def fit_incremental(self, data_generator, max_memory_samples=500000):
        """
        增量训练模型（分批加载数据，节省内存）
        
        Args:
            data_generator: 生成器函数，每次yield (X_batch, y_batch)
            max_memory_samples: 内存中最多保留的样本数（默认50万，约11GB内存）
        """
        print("=== 分批加载训练模式 ===")
        print(f"内存限制: 最多同时加载 {max_memory_samples:,} 个样本")
        
        # 第一步：计算scaler的统计信息（使用部分样本）
        print("\n步骤1/3: 计算特征缩放器统计信息...")
        all_X_for_scaler = []
        sample_count = 0
        max_samples_for_scaler = min(100000, max_memory_samples // 5)  # 使用最多10万样本计算scaler
        
        gen = data_generator()
        for X_batch, y_batch in gen:
            all_X_for_scaler.append(X_batch)
            sample_count += len(X_batch)
            if sample_count >= max_samples_for_scaler:
                break
        
        if all_X_for_scaler:
            X_for_scaler = np.vstack(all_X_for_scaler)
            print(f"使用 {len(X_for_scaler):,} 个样本计算scaler统计信息...")
            self.scaler.fit(X_for_scaler)
            del X_for_scaler, all_X_for_scaler
            gc.collect()
            print("✓ Scaler计算完成")
        else:
            raise ValueError("没有数据用于计算scaler")
        
        # 第二步：分批累积数据并训练
        print("\n步骤2/3: 分批加载数据并训练...")
        accumulated_X = []
        accumulated_y = []
        total_processed = 0
        batch_count = 0
        
        # 重新创建生成器
        gen = data_generator()
        for X_batch, y_batch in gen:
            accumulated_X.append(X_batch)
            accumulated_y.append(y_batch)
            total_processed += len(X_batch)
            batch_count += 1
            
            # 当累积的数据达到内存限制时，进行训练
            current_samples = sum(len(x) for x in accumulated_X)
            if current_samples >= max_memory_samples:
                print(f"\n  累积了 {current_samples:,} 个样本，开始训练...")
                X_train_batch = np.vstack(accumulated_X)
                y_train_batch = np.concatenate(accumulated_y)
                
                # 缩放特征
                X_train_batch_scaled = self.scaler.transform(X_train_batch)
                
                # 训练（如果是第一次，直接训练；否则使用warm_start）
                if not hasattr(self, '_is_trained'):
                    print("  首次训练...")
                    self.classifier.fit(X_train_batch_scaled, y_train_batch)
                    self._is_trained = True
                else:
                    # RandomForest的warm_start需要n_estimators相同
                    # 这里我们重新训练（或者可以累积更多数据）
                    print("  使用累积数据重新训练...")
                    # 为了节省时间，可以只使用部分数据
                    # 或者使用warm_start（但需要固定n_estimators）
                    self.classifier.fit(X_train_batch_scaled, y_train_batch)
                
                print(f"  ✓ 已处理: {total_processed:,} 样本")
                
                # 清空累积数据
                del accumulated_X, accumulated_y, X_train_batch, y_train_batch, X_train_batch_scaled
                accumulated_X = []
                accumulated_y = []
                gc.collect()
        
        # 处理剩余的数据
        if accumulated_X:
            print(f"\n  处理最后 {sum(len(x) for x in accumulated_X):,} 个样本...")
            X_train_batch = np.vstack(accumulated_X)
            y_train_batch = np.concatenate(accumulated_y)
            X_train_batch_scaled = self.scaler.transform(X_train_batch)
            
            if not hasattr(self, '_is_trained'):
                self.classifier.fit(X_train_batch_scaled, y_train_batch)
            else:
                self.classifier.fit(X_train_batch_scaled, y_train_batch)
            
            del accumulated_X, accumulated_y, X_train_batch, y_train_batch, X_train_batch_scaled
            gc.collect()
        
        print(f"\n步骤3/3: 训练完成！")
        print(f"总共处理: {total_processed:,} 个样本，{batch_count} 个批次")
        
    def predict(self, X):
        """预测类别"""
        X_scaled = self.scaler.transform(X)
        return self.classifier.predict(X_scaled)
    
    def predict_proba(self, X):
        """预测概率"""
        X_scaled = self.scaler.transform(X)
        return self.classifier.predict_proba(X_scaled)
    
    def save(self, filepath):
        """保存模型"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'classifier': self.classifier,
                'scaler': self.scaler,
                'feature_names': self.feature_names
            }, f)
        print(f"模型已保存到: {filepath}")


def flatten_dict(d, max_depth=5, current_depth=0):
    """
    递归展开字典为扁平列表
    
    Args:
        d: 字典或列表
        max_depth: 最大递归深度
        current_depth: 当前深度
    
    Returns:
        扁平化的数值列表
    """
    if current_depth >= max_depth:
        return []
    
    result = []
    try:
        if isinstance(d, dict):
            # 按键排序以确保一致性
            for key in sorted(d.keys()):
                val = d[key]
                if isinstance(val, dict):
                    # 递归展开嵌套字典
                    result.extend(flatten_dict(val, max_depth, current_depth + 1))
                elif isinstance(val, list):
                    # 递归展开列表
                    result.extend(flatten_dict(val, max_depth, current_depth + 1))
                elif isinstance(val, (int, float)):
                    result.append(float(val))
                elif isinstance(val, bool):
                    result.append(float(val))
                elif isinstance(val, str):
                    # 尝试转换为数字
                    try:
                        result.append(float(val))
                    except (ValueError, TypeError):
                        result.append(0.0)
                elif val is None:
                    result.append(0.0)
                else:
                    # 未知类型，尝试转换或跳过
                    try:
                        result.append(float(val))
                    except (ValueError, TypeError):
                        result.append(0.0)
        elif isinstance(d, list):
            for item in d:
                if isinstance(item, dict):
                    result.extend(flatten_dict(item, max_depth, current_depth + 1))
                elif isinstance(item, list):
                    result.extend(flatten_dict(item, max_depth, current_depth + 1))
                elif isinstance(item, (int, float)):
                    result.append(float(item))
                elif isinstance(item, bool):
                    result.append(float(item))
                elif isinstance(item, str):
                    try:
                        result.append(float(item))
                    except (ValueError, TypeError):
                        result.append(0.0)
                elif item is None:
                    result.append(0.0)
                else:
                    try:
                        result.append(float(item))
                    except (ValueError, TypeError):
                        result.append(0.0)
        else:
            # 单个值
            if isinstance(d, (int, float)):
                result.append(float(d))
            elif isinstance(d, bool):
                result.append(float(d))
            elif isinstance(d, str):
                try:
                    result.append(float(d))
                except (ValueError, TypeError):
                    result.append(0.0)
            elif d is None:
                result.append(0.0)
            else:
                try:
                    result.append(float(d))
                except (ValueError, TypeError):
                    result.append(0.0)
    except Exception as e:
        # 如果展开过程中出错，返回空列表或部分结果
        print(f"警告: flatten_dict出错 (depth={current_depth}): {e}")
    
    return result


def load_ember_jsonl_generator(file_path, batch_size=10000, max_samples=None):
    """
    生成器函数：分批从JSONL文件加载EMBER特征（节省内存）
    
    Args:
        file_path: JSONL文件路径
        batch_size: 每批加载的样本数
        max_samples: 最大加载样本数（None表示加载全部）
    
    Yields:
        (features_batch, labels_batch): 每批的特征和标签
    """
    features_batch = []
    labels_batch = []
    count = 0
    
    with open(file_path, 'r') as f:
        for line in f:
            if max_samples and count >= max_samples:
                break
            
            try:
                data = json.loads(line.strip())
                
                if 'label' not in data:
                    continue
                
                label = data['label']
                if label not in [0, 1]:
                    continue
                
                # 提取特征向量（复用之前的代码逻辑）
                feature_vector = _extract_feature_vector(data)
                
                features_batch.append(feature_vector)
                labels_batch.append(label)
                count += 1
                
                # 当达到batch_size时，yield一批数据
                if len(features_batch) >= batch_size:
                    features_array = np.array(features_batch, dtype=np.float32)
                    labels_array = np.array(labels_batch, dtype=np.int32)
                    yield features_array, labels_array
                    features_batch = []
                    labels_batch = []
                    gc.collect()
                    
            except Exception as e:
                continue
    
    # 处理剩余的数据
    if features_batch:
        features_array = np.array(features_batch, dtype=np.float32)
        labels_array = np.array(labels_batch, dtype=np.int32)
        yield features_array, labels_array


def _extract_feature_vector(data):
    """从JSON数据中提取特征向量（复用之前的逻辑）"""
    feature_vector = []
    
    # histogram: 256维列表
    if 'histogram' in data and data['histogram'] is not None:
        hist = data['histogram']
        if isinstance(hist, list):
            hist_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in hist[:256]]
            feature_vector.extend(hist_vals)
        elif isinstance(hist, dict):
            hist_vals = flatten_dict(hist)[:256]
            if len(hist_vals) < 256:
                hist_vals.extend([0] * (256 - len(hist_vals)))
            feature_vector.extend(hist_vals)
        else:
            feature_vector.extend([0] * 256)
    else:
        feature_vector.extend([0] * 256)
    
    # byteentropy: 256维列表
    if 'byteentropy' in data and data['byteentropy'] is not None:
        be = data['byteentropy']
        if isinstance(be, list):
            be_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in be[:256]]
            feature_vector.extend(be_vals)
        elif isinstance(be, dict):
            be_vals = flatten_dict(be)[:256]
            if len(be_vals) < 256:
                be_vals.extend([0] * (256 - len(be_vals)))
            feature_vector.extend(be_vals)
        else:
            feature_vector.extend([0] * 256)
    else:
        feature_vector.extend([0] * 256)
    
    # strings: 字典，需要展开成104维
    if 'strings' in data and data['strings'] is not None:
        strings = data['strings']
        if isinstance(strings, dict):
            feature_vector.append(float(strings.get('numstrings', 0)))
            feature_vector.append(float(strings.get('avlength', 0)))
            printabledist = strings.get('printabledist', [])
            if isinstance(printabledist, list):
                printabledist_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in printabledist]
                if len(printabledist_vals) < 100:
                    printabledist_vals.extend([0] * (100 - len(printabledist_vals)))
                feature_vector.extend(printabledist_vals[:100])
            elif isinstance(printabledist, dict):
                printabledist_vals = flatten_dict(printabledist)[:100]
                if len(printabledist_vals) < 100:
                    printabledist_vals.extend([0] * (100 - len(printabledist_vals)))
                feature_vector.extend(printabledist_vals[:100])
            else:
                feature_vector.extend([0] * 100)
            feature_vector.append(float(strings.get('printables', 0)))
            feature_vector.append(float(strings.get('entropy', 0)))
        elif isinstance(strings, list):
            feature_vector.extend(strings[:104])
        else:
            feature_vector.extend([0] * 104)
    else:
        feature_vector.extend([0] * 104)
    
    # general: 字典，需要展开成10维
    if 'general' in data and data['general'] is not None:
        general = data['general']
        if isinstance(general, dict):
            feature_vector.append(float(general.get('size', 0)))
            feature_vector.append(float(general.get('vsize', 0)))
            feature_vector.append(float(general.get('has_debug', 0)))
            feature_vector.append(float(general.get('exports', 0)))
            feature_vector.append(float(general.get('imports', 0)))
            feature_vector.append(float(general.get('has_relocations', 0)))
            feature_vector.append(float(general.get('has_resources', 0)))
            feature_vector.append(float(general.get('has_signature', 0)))
            feature_vector.append(float(general.get('has_tls', 0)))
            feature_vector.append(float(general.get('symbols', 0)))
        elif isinstance(general, list):
            feature_vector.extend(general[:10])
        else:
            feature_vector.extend([0] * 10)
    else:
        feature_vector.extend([0] * 10)
    
    # header: 字典，需要展开成62维
    if 'header' in data and data['header'] is not None:
        header = data['header']
        if isinstance(header, dict):
            header_values = flatten_dict(header)
            if len(header_values) < 62:
                header_values.extend([0] * (62 - len(header_values)))
            feature_vector.extend(header_values[:62])
        elif isinstance(header, list):
            feature_vector.extend(header[:62])
        else:
            feature_vector.extend([0] * 62)
    else:
        feature_vector.extend([0] * 62)
    
    # section: 字典，需要展开成255维
    if 'section' in data and data['section'] is not None:
        section = data['section']
        if isinstance(section, dict):
            section_values = flatten_dict(section)
            if len(section_values) < 255:
                section_values.extend([0] * (255 - len(section_values)))
            feature_vector.extend(section_values[:255])
        elif isinstance(section, list):
            feature_vector.extend(section[:255])
        else:
            feature_vector.extend([0] * 255)
    else:
        feature_vector.extend([0] * 255)
    
    # imports: 字典，需要展开成1280维
    if 'imports' in data and data['imports'] is not None:
        imports = data['imports']
        if isinstance(imports, dict):
            imports_values = flatten_dict(imports)
            if len(imports_values) < 1280:
                imports_values.extend([0] * (1280 - len(imports_values)))
            feature_vector.extend(imports_values[:1280])
        elif isinstance(imports, list):
            feature_vector.extend(imports[:1280])
        else:
            feature_vector.extend([0] * 1280)
    else:
        feature_vector.extend([0] * 1280)
    
    # exports: 列表，128维
    if 'exports' in data and data['exports'] is not None:
        exports = data['exports']
        if isinstance(exports, list):
            exports_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in exports[:128]]
            feature_vector.extend(exports_vals)
        elif isinstance(exports, dict):
            exports_values = flatten_dict(exports)
            if len(exports_values) < 128:
                exports_values.extend([0] * (128 - len(exports_values)))
            feature_vector.extend(exports_values[:128])
        else:
            feature_vector.extend([0] * 128)
    else:
        feature_vector.extend([0] * 128)
    
    # datadirectories: 列表，30维
    if 'datadirectories' in data and data['datadirectories'] is not None:
        dd = data['datadirectories']
        if isinstance(dd, list):
            dd_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in dd[:30]]
            feature_vector.extend(dd_vals)
        elif isinstance(dd, dict):
            dd_values = flatten_dict(dd)
            if len(dd_values) < 30:
                dd_values.extend([0] * (30 - len(dd_values)))
            feature_vector.extend(dd_values[:30])
        else:
            feature_vector.extend([0] * 30)
    else:
        feature_vector.extend([0] * 30)
    
    # 确保特征向量长度正确 (2381维)
    if len(feature_vector) != 2381:
        if len(feature_vector) < 2381:
            feature_vector.extend([0] * (2381 - len(feature_vector)))
        else:
            feature_vector = feature_vector[:2381]
    
    return feature_vector


def load_ember_jsonl(file_path, max_samples=None):
    """
    从JSONL文件加载EMBER特征
    
    Args:
        file_path: JSONL文件路径
        max_samples: 最大加载样本数（None表示加载全部）
    
    Returns:
        features: numpy数组，形状为(n_samples, n_features)
        labels: numpy数组，形状为(n_samples,)
    """
    print(f"正在加载: {file_path}")
    
    features_list = []
    labels_list = []
    
    # EMBER特征字段（按顺序）
    feature_fields = [
        'histogram',      # 256维
        'byteentropy',    # 256维
        'strings',        # 104维
        'general',        # 10维
        'header',         # 62维
        'section',        # 255维
        'imports',        # 1280维
        'exports',        # 128维
        'datadirectories' # 30维
    ]
    
    count = 0
    with open(file_path, 'r') as f:
        for line in tqdm(f, desc="读取JSONL"):
            if max_samples and count >= max_samples:
                break
                
            try:
                data = json.loads(line.strip())
                
                # 检查是否有标签
                if 'label' not in data:
                    continue
                
                label = data['label']
                # 只处理有效标签 (0=良性, 1=恶意)
                if label not in [0, 1]:
                    continue
                
                # 提取特征向量
                feature_vector = []
                
                # histogram: 256维列表
                if 'histogram' in data and data['histogram'] is not None:
                    hist = data['histogram']
                    if isinstance(hist, list):
                        # 确保所有元素都是数字
                        hist_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in hist[:256]]
                        feature_vector.extend(hist_vals)
                    elif isinstance(hist, dict):
                        # 如果是字典，展开它
                        hist_vals = flatten_dict(hist)[:256]
                        if len(hist_vals) < 256:
                            hist_vals.extend([0] * (256 - len(hist_vals)))
                        feature_vector.extend(hist_vals)
                    else:
                        feature_vector.extend([0] * 256)
                else:
                    feature_vector.extend([0] * 256)
                
                # byteentropy: 256维列表
                if 'byteentropy' in data and data['byteentropy'] is not None:
                    be = data['byteentropy']
                    if isinstance(be, list):
                        # 确保所有元素都是数字
                        be_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in be[:256]]
                        feature_vector.extend(be_vals)
                    elif isinstance(be, dict):
                        # 如果是字典，展开它
                        be_vals = flatten_dict(be)[:256]
                        if len(be_vals) < 256:
                            be_vals.extend([0] * (256 - len(be_vals)))
                        feature_vector.extend(be_vals)
                    else:
                        feature_vector.extend([0] * 256)
                else:
                    feature_vector.extend([0] * 256)
                
                # strings: 字典，需要展开成104维
                if 'strings' in data and data['strings'] is not None:
                    strings = data['strings']
                    if isinstance(strings, dict):
                        # 按照EMBER特征顺序展开字典
                        # strings特征: numstrings, avlength, printabledist(100), printables, entropy
                        feature_vector.append(float(strings.get('numstrings', 0)))
                        feature_vector.append(float(strings.get('avlength', 0)))
                        printabledist = strings.get('printabledist', [])
                        if isinstance(printabledist, list):
                            # printabledist可能有96或100个元素，确保扩展到100
                            printabledist_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in printabledist]
                            if len(printabledist_vals) < 100:
                                printabledist_vals.extend([0] * (100 - len(printabledist_vals)))
                            feature_vector.extend(printabledist_vals[:100])
                        elif isinstance(printabledist, dict):
                            printabledist_vals = flatten_dict(printabledist)[:100]
                            if len(printabledist_vals) < 100:
                                printabledist_vals.extend([0] * (100 - len(printabledist_vals)))
                            feature_vector.extend(printabledist_vals[:100])
                        else:
                            feature_vector.extend([0] * 100)
                        feature_vector.append(float(strings.get('printables', 0)))
                        feature_vector.append(float(strings.get('entropy', 0)))
                    elif isinstance(strings, list):
                        feature_vector.extend(strings[:104])
                    else:
                        feature_vector.extend([0] * 104)
                else:
                    feature_vector.extend([0] * 104)
                
                # general: 字典，需要展开成10维
                if 'general' in data and data['general'] is not None:
                    general = data['general']
                    if isinstance(general, dict):
                        # general特征: size, vsize, has_debug, exports, imports, has_relocations, has_resources, has_signature, has_tls, symbols
                        feature_vector.append(float(general.get('size', 0)))
                        feature_vector.append(float(general.get('vsize', 0)))
                        feature_vector.append(float(general.get('has_debug', 0)))
                        feature_vector.append(float(general.get('exports', 0)))
                        feature_vector.append(float(general.get('imports', 0)))
                        feature_vector.append(float(general.get('has_relocations', 0)))
                        feature_vector.append(float(general.get('has_resources', 0)))
                        feature_vector.append(float(general.get('has_signature', 0)))
                        feature_vector.append(float(general.get('has_tls', 0)))
                        feature_vector.append(float(general.get('symbols', 0)))
                    elif isinstance(general, list):
                        feature_vector.extend(general[:10])
                    else:
                        feature_vector.extend([0] * 10)
                else:
                    feature_vector.extend([0] * 10)
                
                # header: 字典，需要展开成62维
                if 'header' in data and data['header'] is not None:
                    header = data['header']
                    if isinstance(header, dict):
                        header_values = flatten_dict(header)
                        # 确保是62维
                        if len(header_values) < 62:
                            header_values.extend([0] * (62 - len(header_values)))
                        feature_vector.extend(header_values[:62])
                    elif isinstance(header, list):
                        feature_vector.extend(header[:62])
                    else:
                        feature_vector.extend([0] * 62)
                else:
                    feature_vector.extend([0] * 62)
                
                # section: 字典，需要展开成255维
                if 'section' in data and data['section'] is not None:
                    section = data['section']
                    if isinstance(section, dict):
                        section_values = flatten_dict(section)
                        # 确保是255维
                        if len(section_values) < 255:
                            section_values.extend([0] * (255 - len(section_values)))
                        feature_vector.extend(section_values[:255])
                    elif isinstance(section, list):
                        feature_vector.extend(section[:255])
                    else:
                        feature_vector.extend([0] * 255)
                else:
                    feature_vector.extend([0] * 255)
                
                # imports: 字典，需要展开成1280维
                if 'imports' in data and data['imports'] is not None:
                    imports = data['imports']
                    if isinstance(imports, dict):
                        imports_values = flatten_dict(imports)
                        # 确保是1280维
                        if len(imports_values) < 1280:
                            imports_values.extend([0] * (1280 - len(imports_values)))
                        feature_vector.extend(imports_values[:1280])
                    elif isinstance(imports, list):
                        feature_vector.extend(imports[:1280])
                    else:
                        feature_vector.extend([0] * 1280)
                else:
                    feature_vector.extend([0] * 1280)
                
                # exports: 列表，128维
                if 'exports' in data and data['exports'] is not None:
                    exports = data['exports']
                    if isinstance(exports, list):
                        exports_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in exports[:128]]
                        feature_vector.extend(exports_vals)
                    elif isinstance(exports, dict):
                        exports_values = flatten_dict(exports)
                        if len(exports_values) < 128:
                            exports_values.extend([0] * (128 - len(exports_values)))
                        feature_vector.extend(exports_values[:128])
                    else:
                        feature_vector.extend([0] * 128)
                else:
                    feature_vector.extend([0] * 128)
                
                # datadirectories: 列表，30维
                if 'datadirectories' in data and data['datadirectories'] is not None:
                    dd = data['datadirectories']
                    if isinstance(dd, list):
                        dd_vals = [float(x) if isinstance(x, (int, float)) else 0.0 for x in dd[:30]]
                        feature_vector.extend(dd_vals)
                    elif isinstance(dd, dict):
                        dd_values = flatten_dict(dd)
                        if len(dd_values) < 30:
                            dd_values.extend([0] * (30 - len(dd_values)))
                        feature_vector.extend(dd_values[:30])
                    else:
                        feature_vector.extend([0] * 30)
                else:
                    feature_vector.extend([0] * 30)
                
                # 确保特征向量长度正确 (2381维)
                if len(feature_vector) != 2381:
                    # 调整长度
                    if len(feature_vector) < 2381:
                        feature_vector.extend([0] * (2381 - len(feature_vector)))
                    else:
                        feature_vector = feature_vector[:2381]
                
                features_list.append(feature_vector)
                labels_list.append(label)
                count += 1
                
            except json.JSONDecodeError as e:
                print(f"JSON解析错误: {e}")
                continue
            except Exception as e:
                import traceback
                print(f"处理行时出错: {e}")
                print(f"错误详情: {traceback.format_exc()}")
                # 只打印前几个错误的详细信息
                if count < 3:
                    print(f"问题数据示例: {json.dumps(data, indent=2)[:500]}")
                continue
    
    if not features_list:
        raise ValueError(f"未能从 {file_path} 加载任何有效数据")
    
    features = np.array(features_list, dtype=np.float32)
    labels = np.array(labels_list, dtype=np.int32)
    
    print(f"加载完成: {len(features)} 个样本, {features.shape[1]} 个特征")
    print(f"标签分布: {np.sum(labels == 1)} 恶意, {np.sum(labels == 0)} 良性")
    
    return features, labels


def load_multiple_jsonl_files(file_paths, max_samples_per_file=None):
    """
    从多个JSONL文件加载数据
    
    Args:
        file_paths: 文件路径列表
        max_samples_per_file: 每个文件最大加载样本数
    
    Returns:
        features: 合并后的特征数组
        labels: 合并后的标签数组
    """
    all_features = []
    all_labels = []
    
    for file_path in file_paths:
        file_path = Path(file_path)
        if not file_path.exists():
            print(f"警告: 文件不存在 {file_path}")
            continue
        
        try:
            features, labels = load_ember_jsonl(file_path, max_samples_per_file)
            all_features.append(features)
            all_labels.append(labels)
        except Exception as e:
            print(f"加载 {file_path} 时出错: {e}")
            continue
    
    if not all_features:
        raise ValueError("未能加载任何数据文件")
    
    # 合并所有数据
    print("\n合并所有数据...")
    X = np.vstack(all_features)
    y = np.concatenate(all_labels)
    
    print(f"最终数据集: {X.shape[0]} 个样本, {X.shape[1]} 个特征")
    print(f"标签分布: {np.sum(y == 1)} 恶意, {np.sum(y == 0)} 良性")
    
    return X, y


def evaluate_model(model, X_test, y_test):
    """评估模型性能"""
    print("\n=== 评估模型 ===")
    
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]  # 恶意软件概率
    
    # 计算指标
    acc = accuracy_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)  # TPR (True Positive Rate)
    pre = precision_score(y_test, y_pred)
    f1s = f1_score(y_test, y_pred)
    
    print(f"准确率 (Accuracy):  {acc:.4f}")
    print(f"召回率 (Recall/TPR): {rec:.4f}")
    print(f"精确率 (Precision): {pre:.4f}")
    print(f"F1分数:             {f1s:.4f}")
    
    # 混淆矩阵
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    print(f"\n混淆矩阵:")
    print(f"真阴性 (TN):  {tn}")
    print(f"假阳性 (FP):  {fp}")
    print(f"假阴性 (FN):  {fn}")
    print(f"真阳性 (TP):  {tp}")
    
    # 计算FPR和FNR
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    
    print(f"\n假阳性率 (FPR): {fpr:.4f} (目标: ≤ 0.01)")
    print(f"假阴性率 (FNR): {fnr:.4f}")
    print(f"真阳性率 (TPR): {tpr:.4f} (目标: ≥ 0.95)")
    
    return {
        'accuracy': acc,
        'recall': rec,
        'precision': pre,
        'f1': f1s,
        'fpr': fpr,
        'fnr': fnr,
        'tpr': tpr
    }


def main():
    parser = argparse.ArgumentParser(description='训练EMBER恶意软件检测模型')
    parser.add_argument('--train-dir', type=str, required=True,
                        help='训练数据目录（包含train_features_*.jsonl文件）')
    parser.add_argument('--test-dir', type=str, default=None,
                        help='测试数据目录（可选）')
    parser.add_argument('--output', type=str, default='ember_model.pickle',
                        help='输出模型文件路径')
    parser.add_argument('--max-samples', type=int, default=None,
                        help='每个文件最大加载样本数（用于快速测试）')
    parser.add_argument('--test-split', type=float, default=0.2,
                        help='训练/测试集分割比例')
    parser.add_argument('--random-state', type=int, default=42,
                        help='随机种子')
    parser.add_argument('--batch-size', type=int, default=50000,
                        help='分批加载时的批次大小（用于节省内存，默认50000）')
    parser.add_argument('--use-batch', action='store_true',
                        help='使用分批加载模式（节省内存，适合大数据集）')
    parser.add_argument('--sample-ratio', type=float, default=1.0,
                        help='采样比例（0.0-1.0），用于快速训练，例如0.1表示使用10%%的数据')
    
    args = parser.parse_args()
    
    # 查找训练文件
    train_dir = Path(args.train_dir)
    train_files = sorted(train_dir.glob('train_features_*.jsonl'))
    
    if not train_files:
        raise ValueError(f"在 {train_dir} 中未找到训练文件")
    
    print(f"找到 {len(train_files)} 个训练文件")
    
    # 加载训练数据
    print("\n=== 加载训练数据 ===")
    
    if args.use_batch:
        # 分批加载模式（节省内存）
        print(f"使用分批加载模式（批次大小: {args.batch_size}）")
        print("注意：分批模式会先采样部分数据计算scaler，然后使用所有数据训练")
        
        # 创建数据生成器
        def train_data_generator():
            for file_path in train_files:
                file_path = Path(file_path)
                if not file_path.exists():
                    continue
                for X_batch, y_batch in load_ember_jsonl_generator(
                    file_path, 
                    batch_size=args.batch_size,
                    max_samples=args.max_samples
                ):
                    yield X_batch, y_batch
        
        # 使用增量训练
        model = EMBERModel()
        max_memory = int(args.batch_size * 10)  # 批次大小的10倍作为内存限制
        model.fit_incremental(train_data_generator, max_memory_samples=max_memory)
        
        # 保存模型
        print(f"\n=== 保存模型 ===")
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        model.save(output_path)
        
        print("\n=== 训练完成 ===")
        print(f"模型已保存到: {output_path}")
        print("\n注意：分批模式下未进行测试集评估")
        print("如需评估，请使用标准模式加载测试数据")
        return
    
    # 标准模式：一次性加载（如果数据量大可能内存不足）
    if args.sample_ratio < 1.0:
        print(f"使用采样模式（采样比例: {args.sample_ratio*100:.1f}%）")
    
    X_train, y_train = load_multiple_jsonl_files(
        train_files, 
        max_samples_per_file=args.max_samples
    )
    
    # 如果指定了采样比例，进行采样
    if args.sample_ratio < 1.0 and len(X_train) > 0:
        sample_size = int(len(X_train) * args.sample_ratio)
        indices = np.random.choice(len(X_train), size=sample_size, replace=False)
        X_train = X_train[indices]
        y_train = y_train[indices]
        print(f"采样后数据集大小: {len(X_train)} 个样本")
    
    # 分割训练/验证集
    if args.test_dir:
        # 如果有测试目录，加载测试数据
        test_dir = Path(args.test_dir)
        test_files = sorted(test_dir.glob('test_features*.jsonl'))
        if test_files:
            print("\n=== 加载测试数据 ===")
            X_test, y_test = load_multiple_jsonl_files(
                test_files,
                max_samples_per_file=args.max_samples
            )
        else:
            print("未找到测试文件，使用训练集分割")
            X_train, X_test, y_train, y_test = train_test_split(
                X_train, y_train, 
                test_size=args.test_split,
                random_state=args.random_state,
                stratify=y_train
            )
    else:
        # 从训练集分割
        print(f"\n分割数据集 (测试集比例: {args.test_split})")
        X_train, X_test, y_train, y_test = train_test_split(
            X_train, y_train, 
            test_size=args.test_split,
            random_state=args.random_state,
            stratify=y_train
        )
    
    print(f"训练集: {X_train.shape[0]} 个样本")
    print(f"测试集: {X_test.shape[0]} 个样本")
    
    # 训练模型
    print("\n=== 训练模型 ===")
    model = EMBERModel()
    model.fit(X_train, y_train)
    
    # 评估模型
    metrics = evaluate_model(model, X_test, y_test)
    
    # 保存模型
    print(f"\n=== 保存模型 ===")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    model.save(output_path)
    
    print("\n=== 训练完成 ===")
    print(f"模型已保存到: {output_path}")
    print(f"模型性能:")
    print(f"  - FPR: {metrics['fpr']:.4f} (目标: ≤ 0.01)")
    print(f"  - TPR: {metrics['tpr']:.4f} (目标: ≥ 0.95)")


if __name__ == '__main__':
    main()

