#!/usr/bin/env python3
"""
5个不同的防御模型定义
每个模型使用不同的算法和参数配置
"""

import os
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
import pickle

# ==================== 设置临时目录（通用设置）====================
# 设置临时目录到SCRATCH，避免home目录磁盘配额问题
if 'SCRATCH' in os.environ:
    scratch_tmp = os.path.join(os.environ['SCRATCH'], 'tmp')
    os.makedirs(scratch_tmp, exist_ok=True)
    # 设置所有可能的临时目录环境变量
    os.environ['TMPDIR'] = scratch_tmp
    os.environ['TMP'] = scratch_tmp
    os.environ['TEMPDIR'] = scratch_tmp
    os.environ['TEMP'] = scratch_tmp
# ================================================

# 禁用LightGBM和XGBoost，全部使用scikit-learn（避免磁盘配额问题）
HAS_LIGHTGBM = False  # 强制禁用LightGBM
HAS_XGBOOST = False   # 强制禁用XGBoost

print("ℹ 使用scikit-learn模型（RandomForest和GradientBoosting），避免LightGBM磁盘配额问题")


class BaseModel:
    """基础模型类"""
    
    def __init__(self, model_id, use_gpu=True):
        self.model_id = model_id
        self.use_gpu = use_gpu and (HAS_LIGHTGBM or HAS_XGBOOST)
        self.scaler = MinMaxScaler()
        self.classifier = None
        self.feature_names = None
        
    def fit(self, X, y):
        """训练模型"""
        X_scaled = self.scaler.fit_transform(X)
        self.classifier.fit(X_scaled, y)
        
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
                'feature_names': self.feature_names,
                'model_id': self.model_id
            }, f)
        print(f"模型 {self.model_id} 已保存到: {filepath}")


class Model1_RandomForest_Deep(BaseModel):
    """模型1: RandomForest深度模型 - 更多树，更深深度"""
    
    def __init__(self, use_gpu=True):
        super().__init__("model1_rf_deep", use_gpu)
        # 使用RandomForest替代LightGBM
        self.classifier = RandomForestClassifier(
            n_estimators=1500,  # 更多树以补偿LightGBM的性能
            max_depth=35,
            max_features='sqrt',
            min_samples_split=5,
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=42,
            verbose=1
        )


class Model2_GradientBoosting_Wide(BaseModel):
    """模型2: GradientBoosting宽模型 - 更宽的树结构"""
    
    def __init__(self, use_gpu=True):
        super().__init__("model2_gb_wide", use_gpu)
        # 使用GradientBoosting替代LightGBM
        self.classifier = GradientBoostingClassifier(
            n_estimators=1200,
            max_depth=25,
            learning_rate=0.05,
            subsample=0.9,  # 类似bagging_fraction
            max_features=0.9,  # 类似feature_fraction
            min_samples_split=30,
            min_samples_leaf=10,
            random_state=43,
            verbose=1
        )


class Model3_GradientBoosting(BaseModel):
    """模型3: GradientBoosting模型 - 不同的boosting算法"""
    
    def __init__(self, use_gpu=True):
        super().__init__("model3_gb", use_gpu)
        # 使用GradientBoosting替代XGBoost
        self.classifier = GradientBoostingClassifier(
            n_estimators=1000,
            max_depth=30,
            learning_rate=0.04,
            subsample=0.8,
            max_features=0.8,  # 类似colsample_bytree
            min_samples_split=10,
            min_samples_leaf=3,
            random_state=44,
            verbose=1
        )


class Model4_RandomForest_Ensemble(BaseModel):
    """模型4: RandomForest集成模型 - 经典但有效"""
    
    def __init__(self, use_gpu=True):
        super().__init__("model4_rf_ensemble", use_gpu)
        self.classifier = RandomForestClassifier(
            n_estimators=2000,
            max_depth=40,
            max_features='sqrt',
            min_samples_split=5,
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=45,
            verbose=1
        )


class Model5_RandomForest_Fast(BaseModel):
    """模型5: RandomForest快速模型 - 平衡速度和性能"""
    
    def __init__(self, use_gpu=True):
        super().__init__("model5_rf_fast", use_gpu)
        # 使用RandomForest替代LightGBM
        self.classifier = RandomForestClassifier(
            n_estimators=800,  # 增加树的数量以补偿性能
            max_depth=20,
            max_features='sqrt',
            min_samples_split=25,
            min_samples_leaf=10,
            n_jobs=-1,
            random_state=46,
            verbose=1
        )


# 模型工厂函数
def create_model(model_id, use_gpu=True):
    """根据模型ID创建对应的模型实例"""
    models = {
        "model1": Model1_RandomForest_Deep,
        "model2": Model2_GradientBoosting_Wide,
        "model3": Model3_GradientBoosting,
        "model4": Model4_RandomForest_Ensemble,
        "model5": Model5_RandomForest_Fast,
    }
    
    if model_id not in models:
        raise ValueError(f"未知的模型ID: {model_id}")
    
    return models[model_id](use_gpu=use_gpu)


def get_all_model_ids():
    """获取所有模型ID列表"""
    return ["model1", "model2", "model3", "model4", "model5"]

