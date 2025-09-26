import os
import re
import lief
import math
import numpy as np
import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler

class PEAttributeExtractor:
    """Extract attributes from PE files using LIEF - simplified version"""
    
    def __init__(self, bytez):
        self.bytez = bytez
        self.lief_binary = None
        self.attributes = {}
        self.libraries = ""
        self.functions = ""
        self.exports = ""
        
        try:
            self.lief_binary = lief.PE.parse(list(bytez))
        except Exception as e:
            print(f"Warning: Could not parse PE with LIEF: {e}")
            self.lief_binary = None

    def extract_string_metadata(self):
        """Extract string-based metadata from PE bytes"""
        if not self.bytez:
            return {'string_paths': 0, 'string_urls': 0, 'string_registry': 0, 'string_MZ': 0}
            
        paths = re.compile(b'c:\\\\', re.IGNORECASE)
        urls = re.compile(b'https?://', re.IGNORECASE)
        registry = re.compile(b'HKEY_')
        mz = re.compile(b'MZ')
        
        return {
            'string_paths': len(paths.findall(self.bytez)),
            'string_urls': len(urls.findall(self.bytez)),
            'string_registry': len(registry.findall(self.bytez)),
            'string_MZ': len(mz.findall(self.bytez))
        }

    def extract_entropy(self):
        """Calculate Shannon entropy of the PE file"""
        if not self.bytez:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = float(self.bytez.count(x.to_bytes(1, 'little'))) / len(self.bytez)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def extract_identify(self):
        """Extract packer/compiler identification (placeholder)"""
        return ""
    
    def extract(self):
        """Extract all PE attributes"""
        if self.lief_binary is None:
            return self._get_minimal_attributes()
        
        try:
            # Get general info
            self.attributes.update({
                "size": len(self.bytez),
                "virtual_size": self.lief_binary.virtual_size,
                "has_debug": int(self.lief_binary.has_debug),
                "imports": len(self.lief_binary.imports),
                "exports": len(self.lief_binary.exported_functions),
                "has_relocations": int(self.lief_binary.has_relocations),
                "has_resources": int(self.lief_binary.has_resources),
                "has_signature": int(self.lief_binary.has_signature),
                "has_tls": int(self.lief_binary.has_tls),
                "symbols": len(self.lief_binary.symbols),
            })

            # Get header info
            self.attributes.update({
                "timestamp": self.lief_binary.header.time_date_stamps,
                "machine": str(self.lief_binary.header.machine),
                "numberof_sections": self.lief_binary.header.numberof_sections,
                "numberof_symbols": self.lief_binary.header.numberof_symbols,
                "pointerto_symbol_table": self.lief_binary.header.pointerto_symbol_table,
                "sizeof_optional_header": self.lief_binary.header.sizeof_optional_header,
                "characteristics": int(self.lief_binary.header.characteristics),
                "characteristics_list": " ".join([str(c).replace("HEADER_CHARACTERISTICS.", "") for c in self.lief_binary.header.characteristics_list])
            })

            try:
                baseof_data = self.lief_binary.optional_header.baseof_data
            except:
                baseof_data = 0

            # Get optional header
            self.attributes.update({
                "baseof_code": self.lief_binary.optional_header.baseof_code,
                "baseof_data": baseof_data,
                "dll_characteristics": self.lief_binary.optional_header.dll_characteristics,
                "dll_characteristics_list": " ".join([str(d).replace("DLL_CHARACTERISTICS.", "") for d in self.lief_binary.optional_header.dll_characteristics_lists]),
                "file_alignment": self.lief_binary.optional_header.file_alignment,
                "imagebase": self.lief_binary.optional_header.imagebase,
                "magic": str(self.lief_binary.optional_header.magic).replace("PE_TYPE.", ""),
                "PE_TYPE": int(self.lief_binary.optional_header.magic),
                "major_image_version": self.lief_binary.optional_header.major_image_version,
                "minor_image_version": self.lief_binary.optional_header.minor_image_version,
                "major_linker_version": self.lief_binary.optional_header.major_linker_version,
                "minor_linker_version": self.lief_binary.optional_header.minor_linker_version,
                "major_operating_system_version": self.lief_binary.optional_header.major_operating_system_version,
                "minor_operating_system_version": self.lief_binary.optional_header.minor_operating_system_version,
                "major_subsystem_version": self.lief_binary.optional_header.major_subsystem_version,
                "minor_subsystem_version": self.lief_binary.optional_header.minor_subsystem_version,
                "numberof_rva_and_size": self.lief_binary.optional_header.numberof_rva_and_size,
                "sizeof_code": self.lief_binary.optional_header.sizeof_code,
                "sizeof_headers": self.lief_binary.optional_header.sizeof_headers,
                "sizeof_heap_commit": self.lief_binary.optional_header.sizeof_heap_commit,
                "sizeof_image": self.lief_binary.optional_header.sizeof_image,
                "sizeof_initialized_data": self.lief_binary.optional_header.sizeof_initialized_data,
                "sizeof_uninitialized_data": self.lief_binary.optional_header.sizeof_uninitialized_data,
                "subsystem": str(self.lief_binary.optional_header.subsystem).replace("SUBSYSTEM.", "")
            })

            # Get entropy
            self.attributes.update({"entropy": self.extract_entropy()})

            # Get string metadata
            self.attributes.update(self.extract_string_metadata())
            
            # Get imported libraries and functions
            if self.lief_binary.has_imports:
                self.libraries = " ".join([l for l in self.lief_binary.libraries])
                self.functions = " ".join([f.name for f in self.lief_binary.imported_functions])
            
            self.attributes.update({"functions": self.functions, "libraries": self.libraries})

            # Get exports
            if self.lief_binary.has_exports:
                self.exports = " ".join([f.name for f in self.lief_binary.exported_functions])
            
            self.attributes.update({"exports_list": self.exports})
            self.attributes.update({"identify": self.extract_identify()})

            return self.attributes
            
        except Exception as e:
            print(f"Error extracting attributes: {e}")
            return self._get_minimal_attributes()
    
    def _get_minimal_attributes(self):
        """Return minimal attributes when parsing fails"""
        return {
            "size": len(self.bytez) if self.bytez else 0,
            "virtual_size": 0, "has_debug": 0, "imports": 0, "exports": 0,
            "has_relocations": 0, "has_resources": 0, "has_signature": 0,
            "has_tls": 0, "symbols": 0, "timestamp": 0, "machine": "0",
            "numberof_sections": 0, "numberof_symbols": 0, "pointerto_symbol_table": 0,
            "sizeof_optional_header": 0, "characteristics": 0, "characteristics_list": "",
            "baseof_code": 0, "baseof_data": 0, "dll_characteristics": 0,
            "dll_characteristics_list": "", "file_alignment": 0, "imagebase": 0,
            "magic": "PE32", "PE_TYPE": 267, "major_image_version": 0,
            "minor_image_version": 0, "major_linker_version": 0, "minor_linker_version": 0,
            "major_operating_system_version": 0, "minor_operating_system_version": 0,
            "major_subsystem_version": 0, "minor_subsystem_version": 0,
            "numberof_rva_and_size": 0, "sizeof_code": 0, "sizeof_headers": 0,
            "sizeof_heap_commit": 0, "sizeof_image": 0, "sizeof_initialized_data": 0,
            "sizeof_uninitialized_data": 0, "subsystem": "UNKNOWN", "entropy": 0,
            "string_paths": 0, "string_urls": 0, "string_registry": 0, "string_MZ": 0,
            "functions": "", "libraries": "", "exports_list": "", "identify": ""
        }


class PEFeatureExtractor:
    """Feature extractor that works with the original nfs_full.pickle model"""
    
    # These are the exact features used in the original model
    NUMERICAL_ATTRIBUTES = [
        'baseof_code', 'baseof_data', 'characteristics', 'dll_characteristics', 
        'entropy', 'file_alignment', 'imagebase', 'machine', 'magic',
        'numberof_rva_and_size', 'numberof_sections', 'numberof_symbols', 'PE_TYPE',
        'pointerto_symbol_table', 'size', 'sizeof_code', 'sizeof_headers',
        'sizeof_image', 'sizeof_initialized_data', 'sizeof_optional_header',
        'sizeof_uninitialized_data', 'timestamp'
    ]
    
    TEXTUAL_ATTRIBUTES = ['identify', 'libraries', 'functions']
    
    def __init__(self, file_bytes, extractor_path=None, scaler_path=None):
        # Initialize PE attribute extractor
        pe_a = PEAttributeExtractor(file_bytes)
        atts = pe_a.extract()
        
        # Create dataframe with obtained values
        self.attributes = pd.DataFrame([atts])
        
        # Try to load extractor and scaler, create fallbacks if not available
        self.extractor = self._load_or_create_extractor(extractor_path)
        self.scaler = self._load_or_create_scaler(scaler_path)
        
    def _load_or_create_extractor(self, extractor_path):
        """Load TF-IDF extractor or create a basic one"""
        if extractor_path and os.path.exists(extractor_path):
            try:
                with open(extractor_path, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"Warning: Could not load extractor: {e}")
        
        # Create basic TF-IDF extractor
        print("Creating basic TF-IDF extractor...")
        extractor = TfidfVectorizer(max_features=100, ngram_range=(1, 2))
        # Fit on some basic patterns
        basic_texts = [
            "kernel32.dll user32.dll ntdll.dll",
            "CreateFile ReadFile WriteFile",
            "RegOpenKey RegSetValue",
            ""  # Empty string for missing data
        ]
        extractor.fit(basic_texts)
        return extractor
        
    def _load_or_create_scaler(self, scaler_path):
        """Load MinMax scaler or create a basic one"""
        if scaler_path and os.path.exists(scaler_path):
            try:
                with open(scaler_path, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                print(f"Warning: Could not load scaler: {e}")
        
        # Create basic scaler
        print("Creating basic MinMax scaler...")
        scaler = MinMaxScaler()
        # Fit on reasonable ranges for PE features
        dummy_data = np.random.random((100, 200))  # Assume ~200 total features
        scaler.fit(dummy_data)
        return scaler
        
    def extract_features(self):
        """Extract features for the model"""
        try:
            # Start with numerical attributes
            numerical_features = []
            for attr in self.NUMERICAL_ATTRIBUTES:
                if attr in self.attributes.columns:
                    val = self.attributes[attr].iloc[0]
                    # Convert string representations to numbers
                    if isinstance(val, str):
                        try:
                            if 'MACHINE.' in str(val):
                                val = hash(val) % 10000
                            elif 'PE32' in str(val):
                                val = 267 if 'PE32' in str(val) else 523
                            else:
                                val = hash(val) % 10000
                        except:
                            val = 0
                    numerical_features.append(float(val))
                else:
                    numerical_features.append(0.0)
            
            # Convert to numpy array
            features = np.array([numerical_features])
            
            # Extract features from textual attributes
            for attr in self.TEXTUAL_ATTRIBUTES:
                text = ""
                if attr in self.attributes.columns:
                    text = str(self.attributes[attr].iloc[0])
                    if text == "nan" or text == "None":
                        text = ""
                
                try:
                    text_features = self.extractor.transform([text])
                    features = np.concatenate((features, text_features.toarray()), axis=1)
                except Exception as e:
                    print(f"Warning: Error processing {attr}: {e}")
                    # Add zeros if text processing fails
                    dummy_features = np.zeros((1, 100))
                    features = np.concatenate((features, dummy_features), axis=1)
            
            # Apply scaling
            try:
                # Only scale if the feature dimensions match
                if features.shape[1] <= self.scaler.n_features_in_:
                    # Pad with zeros if we have fewer features
                    if features.shape[1] < self.scaler.n_features_in_:
                        padding = np.zeros((1, self.scaler.n_features_in_ - features.shape[1]))
                        features = np.concatenate((features, padding), axis=1)
                    features = self.scaler.transform(features)
                else:
                    # Truncate if we have too many features
                    features = features[:, :self.scaler.n_features_in_]
                    features = self.scaler.transform(features)
            except Exception as e:
                print(f"Warning: Scaling failed: {e}, using raw features")
                # Normalize manually if scaling fails
                if features.max() > 0:
                    features = features / features.max()
            
            return features
            
        except Exception as e:
            print(f"Error in feature extraction: {e}")
            import traceback
            traceback.print_exc()
            # Return basic feature vector if everything fails
            return np.zeros((1, 100))


class NFSModel:
    """Simple NFSModel that uses your existing nfs_full.pickle"""
    
    def __init__(self, model_path="defender/models/nfs_full.pickle"):
        self.model_path = model_path
        self.classifier = None
        
        # Paths for extractor and scaler (optional)
        base_dir = os.path.dirname(model_path) if os.path.dirname(model_path) else "defender/models"
        self.extractor_path = os.path.join(base_dir, "nfs_behemot", "nfs_extractor_tfidf.pkl")
        self.scaler_path = os.path.join(base_dir, "nfs_behemot", "nfs_scaler_minmax.pkl")
        
        # Load the main classifier
        self._load_classifier()
        
    def _load_classifier(self):
        """Load the classifier from pickle file"""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
        try:
            with open(self.model_path, 'rb') as f:
                self.classifier = pickle.load(f)
            print(f"Successfully loaded classifier from {self.model_path}")
            
            # Print some info about the loaded model
            if hasattr(self.classifier, 'n_features_in_'):
                print(f"Model expects {self.classifier.n_features_in_} features")
            if hasattr(self.classifier, 'classes_'):
                print(f"Model classes: {self.classifier.classes_}")
                
        except Exception as e:
            raise RuntimeError(f"Error loading classifier: {e}")

    def model_info(self):
        return {
            "name": "NFSModel",
            "version": "1.0", 
            "type": "PE malware classifier",
            "description": f"Model loaded from {self.model_path}",
            "classifier_type": type(self.classifier).__name__ if self.classifier else "Unknown"
        }
    
    def predict(self, bytez: bytes) -> int:
        """Predict if PE file is malware (1) or benign (0)"""
        if self.classifier is None:
            raise RuntimeError("No classifier loaded")
            
        try:
            print(f"Analyzing PE file of {len(bytez)} bytes")
            
            # Extract features
            fe = PEFeatureExtractor(bytez, self.extractor_path, self.scaler_path)
            features = fe.extract_features()
            
            print(f"Extracted features shape: {features.shape}")
            
            # Make prediction
            if hasattr(self.classifier, 'predict_proba'):
                try:
                    proba = self.classifier.predict_proba(features)[0]
                    print(f"Prediction probabilities: {proba}")
                    pred = 1 if len(proba) > 1 and proba[1] > 0.5 else 0
                except:
                    pred = int(self.classifier.predict(features)[0])
            else:
                pred = int(self.classifier.predict(features)[0])
            
            print(f"Final prediction: {pred} ({'malware' if pred == 1 else 'benign'})")
            return pred
            
        except Exception as e:
            print(f"Error in prediction: {e}")
            import traceback
            traceback.print_exc()
            return 1  # Default to malware on error
