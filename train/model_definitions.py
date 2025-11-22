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

# ==================== 设置临时目录（避免home目录磁盘配额问题）====================
# LightGBM使用boost库，可能不遵循TMPDIR环境变量
# 需要在Python层面强制设置
if 'SCRATCH' in os.environ:
    scratch_tmp = os.path.join(os.environ['SCRATCH'], 'tmp')
    os.makedirs(scratch_tmp, exist_ok=True)
    # 设置所有可能的临时目录环境变量
    os.environ['TMPDIR'] = scratch_tmp
    os.environ['TMP'] = scratch_tmp
    os.environ['TEMPDIR'] = scratch_tmp
    os.environ['TEMP'] = scratch_tmp
    os.environ['BOOST_COMPUTE_CACHE_DIR'] = scratch_tmp
# ================================================

# 尝试导入GPU加速的库
try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("⚠ XGBoost not available, Model3 will use GradientBoostingClassifier")


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


class Model1_LightGBM_Deep(BaseModel):
    """模型1: LightGBM深度模型 - 更多树，更深深度"""
    
    def __init__(self, use_gpu=True):
        super().__init__("model1_lgb_deep", use_gpu)
        if self.use_gpu and HAS_LIGHTGBM:
            device = 'gpu' if os.environ.get('CUDA_VISIBLE_DEVICES') else 'cpu'
            self.classifier = lgb.LGBMClassifier(
                n_estimators=1500,
                max_depth=35,
                learning_rate=0.03,
                num_leaves=63,
                feature_fraction=0.8,
                bagging_fraction=0.8,
                bagging_freq=5,
                min_child_samples=20,
                device=device,
                gpu_platform_id=0,
                gpu_device_id=0,
                random_state=42,
                verbose=1,
                n_jobs=-1
            )
        else:
            self.classifier = RandomForestClassifier(
                n_estimators=1000,
                max_depth=35,
                max_features='sqrt',
                n_jobs=-1,
                random_state=42,
                verbose=1
            )


class Model2_LightGBM_Wide(BaseModel):
    """模型2: LightGBM宽模型 - 更多叶子节点，更宽树"""
    
    def __init__(self, use_gpu=True):
        super().__init__("model2_lgb_wide", use_gpu)
        if self.use_gpu and HAS_LIGHTGBM:
            device = 'gpu' if os.environ.get('CUDA_VISIBLE_DEVICES') else 'cpu'
            self.classifier = lgb.LGBMClassifier(
                n_estimators=1200,
                max_depth=25,
                learning_rate=0.05,
                num_leaves=127,  # 更宽的树
                feature_fraction=0.9,
                bagging_fraction=0.9,
                bagging_freq=3,
                min_child_samples=30,
                device=device,
                gpu_platform_id=0,
                gpu_device_id=0,
                random_state=43,
                verbose=1,
                n_jobs=-1
            )
        else:
            self.classifier = RandomForestClassifier(
                n_estimators=800,
                max_depth=25,
                max_features='log2',
                n_jobs=-1,
                random_state=43,
                verbose=1
            )


class Model3_XGBoost(BaseModel):
    """模型3: XGBoost模型 - 不同的boosting算法"""
    
    def __init__(self, use_gpu=True):
        super().__init__("model3_xgb", use_gpu)
        if self.use_gpu and HAS_XGBOOST:
            tree_method = 'gpu_hist' if os.environ.get('CUDA_VISIBLE_DEVICES') else 'hist'
            self.classifier = xgb.XGBClassifier(
                n_estimators=1000,
                max_depth=30,
                learning_rate=0.04,
                subsample=0.8,
                colsample_bytree=0.8,
                min_child_weight=3,
                tree_method=tree_method,
                random_state=44,
                n_jobs=-1,
                verbosity=1
            )
        else:
            self.classifier = GradientBoostingClassifier(
                n_estimators=800,
                max_depth=30,
                learning_rate=0.05,
                subsample=0.8,
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


class Model5_LightGBM_Fast(BaseModel):
    """模型5: LightGBM快速模型 - 平衡速度和性能"""
    
    def __init__(self, use_gpu=True):
        super().__init__("model5_lgb_fast", use_gpu)
        if self.use_gpu and HAS_LIGHTGBM:
            device = 'gpu' if os.environ.get('CUDA_VISIBLE_DEVICES') else 'cpu'
            self.classifier = lgb.LGBMClassifier(
                n_estimators=800,
                max_depth=20,
                learning_rate=0.06,
                num_leaves=31,
                feature_fraction=0.85,
                bagging_fraction=0.85,
                bagging_freq=5,
                min_child_samples=25,
                device=device,
                gpu_platform_id=0,
                gpu_device_id=0,
                random_state=46,
                verbose=1,
                n_jobs=-1
            )
        else:
            self.classifier = RandomForestClassifier(
                n_estimators=600,
                max_depth=20,
                max_features='sqrt',
                n_jobs=-1,
                random_state=46,
                verbose=1
            )


# 模型工厂函数
def create_model(model_id, use_gpu=True):
    """根据模型ID创建对应的模型实例"""
    models = {
        "model1": Model1_LightGBM_Deep,
        "model2": Model2_LightGBM_Wide,
        "model3": Model3_XGBoost,
        "model4": Model4_RandomForest_Ensemble,
        "model5": Model5_LightGBM_Fast,
    }
    
    if model_id not in models:
        raise ValueError(f"未知的模型ID: {model_id}")
    
    return models[model_id](use_gpu=use_gpu)


def get_all_model_ids():
    """获取所有模型ID列表"""
    return ["model1", "model2", "model3", "model4", "model5"]

