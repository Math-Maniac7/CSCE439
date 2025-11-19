"""
基于EMBER JSONL训练的模型，用于部署

该模型类可以加载训练好的模型，从原始PE文件字节中提取特征并进行预测。
"""

import pickle
import numpy as np
from ember import PEFeatureExtractor


class EMBERJSONLModel:
    """
    基于EMBER特征训练的恶意软件检测模型
    
    该模型使用训练好的分类器对PE文件进行检测。
    特征提取使用EMBER的PEFeatureExtractor，确保与训练时一致。
    """
    
    def __init__(self, model_path, threshold=0.5, name='ember_jsonl'):
        """
        初始化模型
        
        Args:
            model_path: 训练好的模型pickle文件路径
            threshold: 分类阈值（默认0.5）
            name: 模型名称
        """
        self.model_path = model_path
        self.threshold = threshold
        self.name = name
        
        # 加载模型
        print(f"正在加载模型: {model_path}")
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.classifier = model_data['classifier']
                self.scaler = model_data['scaler']
                self.feature_names = model_data.get('feature_names', None)
            print("模型加载成功")
        except Exception as e:
            raise ValueError(f"无法加载模型: {e}")
        
        # 初始化EMBER特征提取器（使用版本2，与训练时一致）
        self.extractor = PEFeatureExtractor(2)
        
    def model_info(self):
        """返回模型信息"""
        return {
            "name": self.name,
            "model_path": self.model_path,
            "threshold": self.threshold,
            "type": "EMBER JSONL trained model",
            "description": "基于EMBER特征训练的恶意软件检测模型"
        }
    
    def extract_features(self, bytez):
        """
        从PE文件字节中提取EMBER特征
        
        Args:
            bytez: PE文件的原始字节
            
        Returns:
            feature_vector: 2381维的特征向量
        """
        try:
            # 使用EMBER提取器提取特征
            features = self.extractor.feature_vector(bytez)
            
            # 确保特征向量是正确的形状
            if len(features) != 2381:
                # 如果特征数量不对，尝试调整
                if len(features) < 2381:
                    # 填充零值
                    features = np.pad(features, (0, 2381 - len(features)), 'constant')
                else:
                    # 截断
                    features = features[:2381]
            
            return np.array(features, dtype=np.float32).reshape(1, -1)
            
        except Exception as e:
            print(f"特征提取错误: {e}")
            # 返回零向量作为fallback
            return np.zeros((1, 2381), dtype=np.float32)
    
    def predict_proba(self, bytez):
        """
        预测恶意软件的概率
        
        Args:
            bytez: PE文件的原始字节
            
        Returns:
            probability: 恶意软件的概率 (0-1之间)
        """
        try:
            # 提取特征
            features = self.extract_features(bytez)
            
            # 特征缩放
            features_scaled = self.scaler.transform(features)
            
            # 预测概率
            proba = self.classifier.predict_proba(features_scaled)[0]
            
            # 返回恶意软件的概率（类别1的概率）
            return proba[1] if len(proba) > 1 else proba[0]
            
        except Exception as e:
            print(f"预测错误: {e}")
            # 默认返回0.5（不确定）
            return 0.5
    
    def predict(self, bytez):
        """
        预测PE文件是否为恶意软件
        
        Args:
            bytez: PE文件的原始字节
            
        Returns:
            result: 0表示良性，1表示恶意
        """
        try:
            proba = self.predict_proba(bytez)
            return int(proba > self.threshold)
        except Exception as e:
            print(f"预测错误: {e}")
            # 默认返回1（保守策略：不确定时标记为恶意）
            return 1


if __name__ == '__main__':
    # 测试代码
    print("EMBER JSONL Model - 测试")
    
    # 这里需要提供模型路径和测试文件
    # model = EMBERJSONLModel('path/to/model.pickle')
    # with open('test.exe', 'rb') as f:
    #     bytez = f.read()
    # result = model.predict(bytez)
    # print(f"预测结果: {result}")
    
    print("请提供模型路径和测试文件进行测试")

