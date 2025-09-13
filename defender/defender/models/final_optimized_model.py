import os
import re
import lief
import math
import numpy as np
import pandas as pd
import pickle
import time
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from copy import deepcopy

class FastPEAttributeExtractor:
    """Optimized PE attribute extractor for competition speed requirements"""
    
    def __init__(self, bytez):
        self.bytez = bytez
        self.attributes = {}
        
        # Parse PE file once
        try:
            self.lief_binary = lief.PE.parse(list(bytez))
        except:
            self.lief_binary = None
    
    def extract_string_metadata(self):
        """Fast string pattern matching"""
        if not self.bytez:
            return {'string_paths': 0, 'string_urls': 0, 'string_registry': 0, 'string_MZ': 0}
        
        # Use single pass through bytes with compiled patterns
        bytez_lower = self.bytez.lower()
        
        return {
            'string_paths': bytez_lower.count(b'c:\\\\'),
            'string_urls': bytez_lower.count(b'http://') + bytez_lower.count(b'https://'),
            'string_registry': bytez_lower.count(b'hkey_'),
            'string_MZ': bytez_lower.count(b'mz')
        }
    
    def extract_entropy(self):
        """Fast entropy calculation using numpy"""
        if not self.bytez:
            return 0
        
        # Use numpy for faster calculation
        byte_counts = np.bincount(np.frombuffer(self.bytez, dtype=np.uint8))
        probabilities = byte_counts[byte_counts > 0] / len(self.bytez)
        return -np.sum(probabilities * np.log2(probabilities))
    
    def extract(self):
        """Extract all PE attributes efficiently"""
        if not self.lief_binary:
            # Return safe defaults if PE parsing fails
            return self._get_default_attributes()
        
        try:
            # Basic file info
            self.attributes.update({
                "size": len(self.bytez),
                "virtual_size": getattr(self.lief_binary, 'virtual_size', 0),
                "has_debug": int(getattr(self.lief_binary, 'has_debug', 0)),
                "imports": len(getattr(self.lief_binary, 'imports', [])),
                "exports": len(getattr(self.lief_binary, 'exported_functions', [])),
                "has_relocations": int(getattr(self.lief_binary, 'has_relocations', 0)),
                "has_resources": int(getattr(self.lief_binary, 'has_resources', 0)),
                "has_signature": int(getattr(self.lief_binary, 'has_signature', 0)),
                "has_tls": int(getattr(self.lief_binary, 'has_tls', 0)),
                "symbols": len(getattr(self.lief_binary, 'symbols', [])),
            })
            
            # Header info - with safe attribute access
            header = getattr(self.lief_binary, 'header', None)
            if header:
                self.attributes.update({
                    "timestamp": getattr(header, 'time_date_stamps', 0),
                    "machine": str(getattr(header, 'machine', 'UNKNOWN')),
                    "numberof_sections": getattr(header, 'numberof_sections', 0),
                    "numberof_symbols": getattr(header, 'numberof_symbols', 0),
                    "pointerto_symbol_table": getattr(header, 'pointerto_symbol_table', 0),
                    "sizeof_optional_header": getattr(header, 'sizeof_optional_header', 0),
                    "characteristics": int(getattr(header, 'characteristics', 0)),
                    "characteristics_list": self._safe_join_characteristics(header)
                })
            else:
                self.attributes.update(self._get_default_header_attributes())
            
            # Optional header
            optional_header = getattr(self.lief_binary, 'optional_header', None)
            if optional_header:
                self.attributes.update({
                    "baseof_code": getattr(optional_header, 'baseof_code', 0),
                    "baseof_data": getattr(optional_header, 'baseof_data', 0),
                    "dll_characteristics": getattr(optional_header, 'dll_characteristics', 0),
                    "dll_characteristics_list": self._safe_join_dll_characteristics(optional_header),
                    "file_alignment": getattr(optional_header, 'file_alignment', 0),
                    "imagebase": getattr(optional_header, 'imagebase', 0),
                    "magic": str(getattr(optional_header, 'magic', 'UNKNOWN')).replace("PE_TYPE.", ""),
                    "PE_TYPE": int(getattr(optional_header, 'magic', 0)),
                    "major_image_version": getattr(optional_header, 'major_image_version', 0),
                    "minor_image_version": getattr(optional_header, 'minor_image_version', 0),
                    "major_linker_version": getattr(optional_header, 'major_linker_version', 0),
                    "minor_linker_version": getattr(optional_header, 'minor_linker_version', 0),
                    "major_operating_system_version": getattr(optional_header, 'major_operating_system_version', 0),
                    "minor_operating_system_version": getattr(optional_header, 'minor_operating_system_version', 0),
                    "major_subsystem_version": getattr(optional_header, 'major_subsystem_version', 0),
                    "minor_subsystem_version": getattr(optional_header, 'minor_subsystem_version', 0),
                    "numberof_rva_and_size": getattr(optional_header, 'numberof_rva_and_size', 0),
                    "sizeof_code": getattr(optional_header, 'sizeof_code', 0),
                    "sizeof_headers": getattr(optional_header, 'sizeof_headers', 0),
                    "sizeof_heap_commit": getattr(optional_header, 'sizeof_heap_commit', 0),
                    "sizeof_image": getattr(optional_header, 'sizeof_image', 0),
                    "sizeof_initialized_data": getattr(optional_header, 'sizeof_initialized_data', 0),
                    "sizeof_uninitialized_data": getattr(optional_header, 'sizeof_uninitialized_data', 0),
                    "subsystem": str(getattr(optional_header, 'subsystem', 'UNKNOWN')).replace("SUBSYSTEM.", "")
                })
            else:
                self.attributes.update(self._get_default_optional_header_attributes())
            
            # Add entropy
            self.attributes["entropy"] = self.extract_entropy()
            
            # Add string metadata
            self.attributes.update(self.extract_string_metadata())
            
            # Extract imports/exports efficiently
            self._extract_imports_exports()
            
        except Exception as e:
            print(f"Error extracting PE attributes: {e}")
            return self._get_default_attributes()
        
        return self.attributes
    
    def _extract_imports_exports(self):
        """Extract import/export information efficiently"""
        libraries = []
        functions = []
        exports = []
        
        # Extract imports
        if getattr(self.lief_binary, 'has_imports', False):
            try:
                for lib in getattr(self.lief_binary, 'libraries', []):
                    libraries.append(lib)
                
                for func in getattr(self.lief_binary, 'imported_functions', []):
                    if hasattr(func, 'name') and func.name:
                        functions.append(func.name)
            except:
                pass
        
        # Extract exports
        if getattr(self.lief_binary, 'has_exports', False):
            try:
                for func in getattr(self.lief_binary, 'exported_functions', []):
                    if hasattr(func, 'name') and func.name:
                        exports.append(func.name)
            except:
                pass
        
        self.attributes.update({
            "functions": " ".join(functions),
            "libraries": " ".join(libraries),
            "exports_list": " ".join(exports),
            "identify": ""  # Placeholder for signature matching
        })
    
    def _safe_join_characteristics(self, header):
        """Safely join characteristics list"""
        try:
            chars_list = getattr(header, 'characteristics_list', [])
            return " ".join([str(c).replace("HEADER_CHARACTERISTICS.", "") for c in chars_list])
        except:
            return ""
    
    def _safe_join_dll_characteristics(self, optional_header):
        """Safely join DLL characteristics list"""
        try:
            dll_chars = getattr(optional_header, 'dll_characteristics_lists', [])
            return " ".join([str(d).replace("DLL_CHARACTERISTICS.", "") for d in dll_chars])
        except:
            return ""
    
    def _get_default_attributes(self):
        """Return default attributes when PE parsing fails"""
        defaults = {
            "size": len(self.bytez) if self.bytez else 0,
            "virtual_size": 0, "has_debug": 0, "imports": 0, "exports": 0,
            "has_relocations": 0, "has_resources": 0, "has_signature": 0,
            "has_tls": 0, "symbols": 0, "entropy": 0,
            "functions": "", "libraries": "", "exports_list": "", "identify": ""
        }
        defaults.update(self._get_default_header_attributes())
        defaults.update(self._get_default_optional_header_attributes())
        defaults.update(self.extract_string_metadata())
        return defaults
    
    def _get_default_header_attributes(self):
        return {
            "timestamp": 0, "machine": "UNKNOWN", "numberof_sections": 0,
            "numberof_symbols": 0, "pointerto_symbol_table": 0,
            "sizeof_optional_header": 0, "characteristics": 0,
            "characteristics_list": ""
        }
    
    def _get_default_optional_header_attributes(self):
        return {
            "baseof_code": 0, "baseof_data": 0, "dll_characteristics": 0,
            "dll_characteristics_list": "", "file_alignment": 0, "imagebase": 0,
            "magic": "UNKNOWN", "PE_TYPE": 0, "major_image_version": 0,
            "minor_image_version": 0, "major_linker_version": 0,
            "minor_linker_version": 0, "major_operating_system_version": 0,
            "minor_operating_system_version": 0, "major_subsystem_version": 0,
            "minor_subsystem_version": 0, "numberof_rva_and_size": 0,
            "sizeof_code": 0, "sizeof_headers": 0, "sizeof_heap_commit": 0,
            "sizeof_image": 0, "sizeof_initialized_data": 0,
            "sizeof_uninitialized_data": 0, "subsystem": "UNKNOWN"
        }


class OptimizedNFSModel:
    """Optimized version of your NFS model for competition requirements"""
    
    # Reduced feature set for speed while maintaining accuracy
    NUMERICAL_ATTRIBUTES = [
        'string_paths', 'string_urls', 'string_registry', 'string_MZ', 'size',
        'virtual_size', 'has_debug', 'imports', 'exports', 'has_relocations',
        'has_resources', 'has_signature', 'has_tls', 'symbols', 'timestamp', 
        'numberof_sections', 'major_image_version', 'minor_image_version', 
        'major_linker_version', 'minor_linker_version', 'major_operating_system_version',
        'minor_operating_system_version', 'major_subsystem_version', 
        'minor_subsystem_version', 'sizeof_code', 'sizeof_headers', 'sizeof_heap_commit',
        'entropy'  # Added entropy as numerical feature
    ]

    CATEGORICAL_ATTRIBUTES = ['machine', 'magic']
    
    # Focus on most important textual features for speed
    TEXTUAL_ATTRIBUTES = ['libraries', 'functions']

    def __init__(self, 
                categorical_extractor=None, 
                textual_extractor=None,
                feature_scaler=None,
                classifier=None):
        
        # Use optimized defaults
        self.base_categorical_extractor = categorical_extractor or OneHotEncoder(handle_unknown="ignore")
        self.base_textual_extractor = textual_extractor or TfidfVectorizer(
            max_features=200,  # Reduced for speed/memory
            lowercase=True,
            stop_words=None,
            ngram_range=(1, 1)  # Only unigrams for speed
        )
        self.base_feature_scaler = feature_scaler or MinMaxScaler()
        self.base_classifier = classifier or RandomForestClassifier(
            n_estimators=50,  # Reduced for speed
            max_depth=15,     # Prevent overfitting
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=42,
            n_jobs=1,  # Single thread for memory control
            class_weight='balanced'
        )
    
    def predict(self, bytez: bytes) -> int:
        """Fast prediction optimized for competition requirements"""
        start_time = time.time()
        
        try:
            # Fast PE attribute extraction
            pe_extractor = FastPEAttributeExtractor(bytez)
            attributes = pe_extractor.extract()
            
            # Convert to DataFrame
            df = pd.DataFrame([attributes])
            
            # Extract features using the trained pipeline
            features = self._extract_features_fast(df)
            
            # Get prediction probabilities
            probabilities = self.classifier.predict_proba(features)[0]
            
            # Use optimized threshold for FPR ≤ 1% and TPR ≥ 95%
            # This threshold should be tuned during training
            malware_threshold = 0.1  # Conservative threshold
            prediction = int(probabilities[1] > malware_threshold)
            
            elapsed_time = time.time() - start_time
            if elapsed_time > 4.0:  # Log slow predictions
                print(f"Warning: Slow prediction took {elapsed_time:.2f} seconds")
            
            print(f"Prediction = {prediction} (prob: {probabilities[prediction]:.3f}, time: {elapsed_time:.3f}s)")
            return prediction
            
        except Exception as e:
            print(f"Error during prediction: {e}")
            # Default to malware (safer for competition)
            return 1
    
    def _extract_features_fast(self, data):
        """Fast feature extraction for single prediction"""
        # Start with numerical features
        features = data[self.NUMERICAL_ATTRIBUTES].values.tolist()

        # Transform categorical features
        cat_features = self.categorical_extractor.transform(
            data[self.CATEGORICAL_ATTRIBUTES].values.tolist()
        ).toarray()
        features = self._append_features(features, cat_features)

        # Transform textual features
        for att in self.TEXTUAL_ATTRIBUTES:
            att_features = self.textual_extractors[att].transform(data[att].values)
            att_features = att_features.toarray()
            features = self._append_features(features, att_features)

        # Scale features
        features = self.feature_scaler.transform(features)
        return features
    
    def _append_features(self, original_features, appended):
        """Efficiently append features"""
        if original_features:
            for l1, l2 in zip(original_features, appended):
                for i in l2:
                    l1.append(i)
            return original_features
        else:
            return appended.tolist()
    
    def fit(self, train_data):
        """Train the model with your existing pipeline"""
        # Follow your existing training logic but with optimizations
        train_labels = train_data["label"]
        train_data = train_data.drop("label", axis=1)
        
        # Initialize train_features with numerical ones
        train_features = train_data[self.NUMERICAL_ATTRIBUTES].values.tolist()

        print("Training categorical features...")
        self.categorical_extractor = deepcopy(self.base_categorical_extractor)
        self.categorical_extractor.fit(train_data[self.CATEGORICAL_ATTRIBUTES].values)
        
        cat_train_features = self.categorical_extractor.transform(
            train_data[self.CATEGORICAL_ATTRIBUTES].values.tolist()
        ).toarray()
        train_features = self._append_features(train_features, cat_train_features)

        print("Training textual features...")
        self.textual_extractors = {}
        for att in self.TEXTUAL_ATTRIBUTES:
            self.textual_extractors[att] = deepcopy(self.base_textual_extractor)
            self.textual_extractors[att].fit(train_data[att].values)
            
            att_features = self.textual_extractors[att].transform(train_data[att].values)
            att_features = att_features.toarray()
            train_features = self._append_features(train_features, att_features)

        print("Normalizing features...")
        self.feature_scaler = deepcopy(self.base_feature_scaler)
        self.feature_scaler.fit(train_features)
        train_features = self.feature_scaler.transform(train_features)

        print("Training classifier...")
        self.classifier = deepcopy(self.base_classifier)
        self.classifier.fit(train_features, train_labels)

        return self

    def model_info(self):
        """Return model information for API"""
        return {
            'name': 'OptimizedNFSMalwareDetector',
            'version': '2.0',
            'features': len(self.NUMERICAL_ATTRIBUTES) + len(self.CATEGORICAL_ATTRIBUTES) + len(self.TEXTUAL_ATTRIBUTES)
        }


class CompetitionNFSModel:
    """Wrapper class compatible with your existing model interface"""
    
    def __init__(self, model_path):
        """Load the trained model from pickle file"""
        if isinstance(model_path, str):
            with open(model_path, 'rb') as f:
                self.nfs_model = pickle.load(f)
        else:
            # model_path is already a file object
            self.nfs_model = pickle.load(model_path)
    
    def predict(self, bytez: bytes) -> int:
        """Main prediction method for the competition"""
        try:
            # Fast PE attribute extraction
            pe_extractor = FastPEAttributeExtractor(bytez)
            attributes = pe_extractor.extract()
            
            # Convert to DataFrame (matching training format)
            df = pd.DataFrame([attributes])
            
            # Use the trained NFS model for prediction
            probabilities = self.nfs_model.predict_proba(df)[0]
            
            # Competition-optimized threshold
            # Tune this based on validation results to meet FPR ≤ 1%, TPR ≥ 95%
            threshold = 0.05  # Very conservative for low FPR
            prediction = int(probabilities[1] > threshold)
            
            print(f"Prediction = {prediction} (malware_prob: {probabilities[1]:.3f})")
            return prediction
            
        except Exception as e:
            print(f"Error during prediction: {e}")
            # Default to malware (safer for AV system)
            return 1
    
    def model_info(self):
        """Return model information"""
        return {
            'name': 'CompetitionNFSMalwareDetector',
            'version': '2.0',
            'type': 'PE_NFS_Model'
        }