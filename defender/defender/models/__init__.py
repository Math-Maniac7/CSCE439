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