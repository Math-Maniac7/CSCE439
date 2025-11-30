# Models package initialization
try:
    from .nfs_model import NFSModel, NeedForSpeedModel, PEAttributeExtractor
    __all__ = ['NFSModel', 'NeedForSpeedModel', 'PEAttributeExtractor']
except ImportError as e:
    print(f"Warning: Could not import NFS models: {e}")
    __all__ = []

try:
    from .dummy_model import DummyModel
    __all__.append('DummyModel')
except ImportError as e:
    print(f"Warning: Could not import DummyModel: {e}")

try:
    from .model1_rf_deep import Model1_RandomForest_Deep
    __all__.append('Model1_RandomForest_Deep')
except ImportError as e:
    print(f"Warning: Could not import Model1: {e}")