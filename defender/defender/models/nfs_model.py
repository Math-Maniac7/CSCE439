import os
import re
import lief
import math
import numpy as np
import pandas as pd
import pickle
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from copy import deepcopy

class PEAttributeExtractor:
    """Extract attributes from PE files using LIEF"""
    
    def __init__(self, bytez):
        self.bytez = bytez
        self.lief_binary = None
        self.attributes = {}
        self.libraries = ""
        self.functions = ""
        self.exports = ""
        
        try:
            # Parse using LIEF
            self.lief_binary = lief.PE.parse(list(bytez))
            print(f"✅ LIEF parsing successful")
        except Exception as e:
            print(f"❌ Error parsing PE with LIEF: {e}")
            self.lief_binary = None

    def extract_string_metadata(self):
        """Extract string-based metadata from PE bytes"""
        if not self.bytez:
            return {
                'string_paths': 0,
                'string_urls': 0,
                'string_registry': 0,
                'string_MZ': 0
            }
            
        # Occurrences of the string 'C:\'. Not actually extracting the path
        paths = re.compile(b'c:\\\\', re.IGNORECASE)
        # Occurrences of http:// or https://. Not actually extracting the URLs
        urls = re.compile(b'https?://', re.IGNORECASE)
        # Occurrences of the string prefix HKEY_. Not actually extracting registry names
        registry = re.compile(b'HKEY_')
        # Crude evidence of an MZ header (dropper?) somewhere in the byte stream
        mz = re.compile(b'MZ')
        
        result = {
            'string_paths': len(paths.findall(self.bytez)),
            'string_urls': len(urls.findall(self.bytez)),
            'string_registry': len(registry.findall(self.bytez)),
            'string_MZ': len(mz.findall(self.bytez))
        }
        
        print(f"🔍 String metadata: {result}")
        return result

    def extract_entropy(self):
        """Calculate Shannon entropy of the PE file"""
        if not self.bytez:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = float(self.bytez.count(x.to_bytes(1, 'little'))) / len(self.bytez)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        
        print(f"📈 Entropy: {entropy:.3f}")
        return entropy

    def extract_identify(self):
        """Extract packer/compiler identification (placeholder)"""
        return ""
    
    def extract(self):
        """Extract all PE attributes"""
        print(f"🔍 Starting PE analysis of {len(self.bytez)} bytes")
        
        if self.lief_binary is None:
            print("⚠️  LIEF parsing failed, using minimal attributes")
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

            print(f"📊 General info - Size: {self.attributes['size']}, Imports: {self.attributes['imports']}, Exports: {self.attributes['exports']}")

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
            self.attributes.update({
                "entropy": self.extract_entropy()
            })

            # Get string metadata
            self.attributes.update(self.extract_string_metadata())
            
            # Get imported libraries and functions
            if self.lief_binary.has_imports:
                self.libraries = " ".join([l for l in self.lief_binary.libraries])
                self.functions = " ".join([f.name for f in self.lief_binary.imported_functions])
                print(f"📚 Found {len(self.lief_binary.libraries)} libraries: {self.libraries[:100]}...")
                print(f"🔧 Found {len(self.lief_binary.imported_functions)} functions: {self.functions[:100]}...")
            else:
                print("📚 No imports found")
            
            self.attributes.update({"functions": self.functions, "libraries": self.libraries})

            # Get exports
            if self.lief_binary.has_exports:
                self.exports = " ".join([f.name for f in self.lief_binary.exported_functions])
                print(f"📤 Found {len(self.lief_binary.exported_functions)} exports: {self.exports[:100]}...")
            else:
                print("📤 No exports found")
            
            self.attributes.update({"exports_list": self.exports})

            # Get identify
            self.attributes.update({"identify": self.extract_identify()})

            print(f"📋 Total attributes extracted: {len(self.attributes)}")
            print(f"📋 Sample attributes: {list(self.attributes.keys())[:10]}")

            return self.attributes
            
        except Exception as e:
            print(f"❌ Error extracting attributes: {e}")
            import traceback
            traceback.print_exc()
            return self._get_minimal_attributes()
    
    def _get_minimal_attributes(self):
        """Return minimal attributes when parsing fails"""
        minimal = {
            "size": len(self.bytez) if self.bytez else 0,
            "virtual_size": 0,
            "has_debug": 0,
            "imports": 0,
            "exports": 0,
            "has_relocations": 0,
            "has_resources": 0,
            "has_signature": 0,
            "has_tls": 0,
            "symbols": 0,
            "timestamp": 0,
            "machine": "MACHINE.UNKNOWN",
            "numberof_sections": 0,
            "numberof_symbols": 0,
            "pointerto_symbol_table": 0,
            "sizeof_optional_header": 0,
            "characteristics": 0,
            "characteristics_list": "",
            "baseof_code": 0,
            "baseof_data": 0,
            "dll_characteristics": 0,
            "dll_characteristics_list": "",
            "file_alignment": 0,
            "imagebase": 0,
            "magic": "PE32",
            "PE_TYPE": 267,
            "major_image_version": 0,
            "minor_image_version": 0,
            "major_linker_version": 0,
            "minor_linker_version": 0,
            "major_operating_system_version": 0,
            "minor_operating_system_version": 0,
            "major_subsystem_version": 0,
            "minor_subsystem_version": 0,
            "numberof_rva_and_size": 0,
            "sizeof_code": 0,
            "sizeof_headers": 0,
            "sizeof_heap_commit": 0,
            "sizeof_image": 0,
            "sizeof_initialized_data": 0,
            "sizeof_uninitialized_data": 0,
            "subsystem": "UNKNOWN",
            "entropy": 0,
            "string_paths": 0,
            "string_urls": 0,
            "string_registry": 0,
            "string_MZ": 0,
            "functions": "",
            "libraries": "",
            "exports_list": "",
            "identify": ""
        }
        
        print(f"⚠️  Using minimal attributes: {len(minimal)} attributes")
        return minimal


class PEFeatureExtractor:
    """Feature extractor that matches the original implementation"""
    
    # These MUST match the original training data
    NUMERICAL_ATTRIBUTES = [
        'baseof_code', 'baseof_data', 'characteristics', 'dll_characteristics', 
        'entropy', 'file_alignment', 'imagebase', 'machine', 'magic',
        'numberof_rva_and_size', 'numberof_sections', 'numberof_symbols', 'PE_TYPE',
        'pointerto_symbol_table', 'size', 'sizeof_code', 'sizeof_headers',
        'sizeof_image', 'sizeof_initialized_data', 'sizeof_optional_header',
        'sizeof_uninitialized_data', 'timestamp'
    ]
    
    TEXTUAL_ATTRIBUTES = ['identify', 'libraries', 'functions']
    
    def __init__(self, file_bytes, extractor_path, scaler_path):
        print(f"🔧 Initializing feature extractor...")
        print(f"🔧 Extractor path: {extractor_path}")
        print(f"🔧 Scaler path: {scaler_path}")
        
        # Initialize PE attribute extractor
        pe_a = PEAttributeExtractor(file_bytes)
        # Get attributes values and names
        atts = pe_a.extract()
        
        # Create dataframe with obtained values
        self.attributes = pd.DataFrame([atts])
        print(f"📋 Attributes DataFrame shape: {self.attributes.shape}")
        print(f"📋 Attributes columns: {list(self.attributes.columns)[:10]}...")
        
        # Load extractor and scaler
        try:
            with open(extractor_path, 'rb') as f:
                self.extractor = pickle.load(f)
            print(f"✅ Loaded TF-IDF extractor with {len(self.extractor.vocabulary_)} vocabulary terms")
        except Exception as e:
            print(f"❌ Error loading extractor: {e}")
            # Create dummy extractor
            self.extractor = TfidfVectorizer(max_features=100)
            self.extractor.fit(["dummy text"])
            print(f"⚠️  Created dummy TF-IDF extractor")
            
        try:
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            print(f"✅ Loaded scaler expecting {self.scaler.n_features_in_} features")
        except Exception as e:
            print(f"❌ Error loading scaler: {e}")
            # Create dummy scaler
            self.scaler = MinMaxScaler()
            self.scaler.fit([[0] * 100])
            print(f"⚠️  Created dummy scaler")
        
    def extract_features(self):
        """Extract features exactly like the original"""
        print(f"🔧 Starting feature extraction...")
        
        try:
            # Start with numerical attributes
            numerical_features = []
            missing_attrs = []
            
            for attr in self.NUMERICAL_ATTRIBUTES:
                if attr in self.attributes.columns:
                    val = self.attributes[attr].iloc[0]
                    # Convert string representations to numbers
                    if isinstance(val, str):
                        try:
                            # Try to extract numeric part from strings like "MACHINE.I386"
                            if 'MACHINE.' in str(val):
                                val = hash(val) % 10000  # Convert to consistent number
                            elif 'PE32' in str(val):
                                val = 267 if 'PE32' in str(val) else 523
                            else:
                                val = hash(val) % 10000
                        except:
                            val = 0
                    numerical_features.append(float(val))
                else:
                    numerical_features.append(0.0)
                    missing_attrs.append(attr)
            
            if missing_attrs:
                print(f"⚠️  Missing numerical attributes: {missing_attrs[:5]}...")
            
            # Convert to numpy array
            features = np.array([numerical_features])
            print(f"📊 Numerical features shape: {features.shape}")
            print(f"📊 Numerical features sample: {features[0][:10]}...")  # First 10 values
            
            # Extract features from each textual attribute
            for a in self.TEXTUAL_ATTRIBUTES:
                print(f"🔤 Processing textual attribute: {a}")
                
                text_content = ""
                if a in self.attributes.columns:
                    text_content = str(self.attributes[a].iloc[0])
                    if text_content in ['nan', 'None', 'null']:
                        text_content = ""
                
                print(f"🔤 Text content for {a}: '{text_content[:100]}...'")  # First 100 chars
                
                try:
                    # extract features from current attribute
                    train_texts = self.extractor.transform([text_content])
                    print(f"🔤 TF-IDF features for {a}: shape {train_texts.shape}, non-zero: {train_texts.nnz}")
                    
                    # concatenate with numerical attributes
                    features = np.concatenate((features, train_texts.toarray()), axis=1)
                    print(f"🔤 Combined features shape after {a}: {features.shape}")
                    
                except Exception as e:
                    print(f"❌ Error processing textual attribute {a}: {e}")
                    # Add dummy features if text processing fails
                    dummy_features = np.zeros((1, 100))  # Assuming 100 features
                    features = np.concatenate((features, dummy_features), axis=1)
                    print(f"⚠️  Added dummy features for {a}")
            
            print(f"⚖️  Features before scaling: shape {features.shape}, min {features.min():.6f}, max {features.max():.6f}")
            print(f"⚖️  Non-zero features before scaling: {np.count_nonzero(features)}/{features.size}")
            
            # Normalize using the scaler
            try:
                original_shape = features.shape
                features = self.scaler.transform(features)
                print(f"✅ Scaling successful: {original_shape} -> {features.shape}")
            except Exception as e:
                print(f"❌ Error in scaling: {e}")
                # If scaling fails, just normalize manually
                if features.max() > 0:
                    features = features / (np.max(features) + 1e-8)
                    print(f"⚠️  Manual normalization applied")
                else:
                    print(f"⚠️  All features are zero - this may indicate a problem")
            
            print(f"✅ Final features: shape {features.shape}, min={features.min():.6f}, max={features.max():.6f}, mean={features.mean():.6f}")
            print(f"✅ Non-zero features: {np.count_nonzero(features)}/{features.size}")
            
            return features
            
        except Exception as e:
            print(f"❌ Error in feature extraction: {e}")
            import traceback
            traceback.print_exc()
            # Return dummy features if everything fails
            dummy_features = np.zeros((1, 500))
            print(f"⚠️  Returning dummy features: {dummy_features.shape}")
            return dummy_features


class NFSModel:
    """Fixed NFSModel that properly handles the feature pipeline"""
    
    def __init__(self, model_file=None, model_path=None):
        print(f"🔧 Initializing NFSModel...")
        
        self.classifier = None
        self.model_path = model_path
        self.extractor_path = None
        self.scaler_path = None
        
        # Set up paths - FIXED for your directory structure
        if model_path:
            base_path = os.path.dirname(model_path)
            self.model_path = model_path
        else:
            base_path = "defender/models"
            self.model_path = os.path.join(base_path, "nfs_full.pickle")
            
        # Updated paths to match your structure
        self.extractor_path = os.path.join(base_path, "nfs_behemot", "nfs_extractor_tfidf.pkl")
        self.scaler_path = os.path.join(base_path, "nfs_behemot", "nfs_scaler_minmax.pkl")
        
        print(f"🔧 Model path: {self.model_path}")
        print(f"🔧 Extractor path: {self.extractor_path}")
        print(f"🔧 Scaler path: {self.scaler_path}")
        
        # Load the main classifier
        if model_file:
            try:
                model_file.seek(0)
                self.classifier = pickle.load(model_file)
                print("✅ Successfully loaded classifier from file object")
            except Exception as e:
                print(f"❌ Error loading classifier from file object: {e}")
        elif self.model_path and os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    self.classifier = pickle.load(f)
                print(f"✅ Successfully loaded classifier from {self.model_path}")
                
                # Print classifier info
                if hasattr(self.classifier, 'n_features_in_'):
                    print(f"📊 Model expects {self.classifier.n_features_in_} features")
                if hasattr(self.classifier, 'classes_'):
                    print(f"📊 Model classes: {self.classifier.classes_}")
                if hasattr(self.classifier, 'n_estimators'):
                    print(f"📊 Model estimators: {self.classifier.n_estimators}")
                    
            except Exception as e:
                print(f"❌ Error loading classifier from path: {e}")
        else:
            print(f"❌ Model file not found: {self.model_path}")
        
        # REMOVED: No more dummy fallback - fail if model doesn't load
        if self.classifier is None:
            raise RuntimeError(f"Could not load classifier from {self.model_path}. Please ensure the model file exists and is valid.")

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
        try:
            print(f"🔍 Analyzing PE file of {len(bytez)} bytes")
            
            # Extract features using the proper pipeline
            fe = PEFeatureExtractor(bytez, self.extractor_path, self.scaler_path)
            features = fe.extract_features()
            
            print(f"✅ Final features shape: {features.shape}")
            print(f"✅ Features summary: min={features.min():.6f}, max={features.max():.6f}, mean={features.mean():.6f}")
            print(f"✅ Non-zero features: {np.count_nonzero(features)}/{features.size}")
            
            # Make prediction
            if hasattr(self.classifier, 'predict_proba'):
                try:
                    proba = self.classifier.predict_proba(features)[0]
                    print(f"🎯 Prediction probabilities: {proba}")
                    pred = 1 if len(proba) > 1 and proba[1] > 0.5 else 0  # 1 = malware, 0 = benign
                except Exception as e:
                    print(f"⚠️  predict_proba failed: {e}, using predict instead")
                    pred = int(self.classifier.predict(features)[0])
            else:
                pred = int(self.classifier.predict(features)[0])
            
            print(f"🎯 Final prediction: {pred} ({'malware' if pred == 1 else 'benign'})")
            return pred
            
        except Exception as e:
            print(f"❌ Error in prediction: {e}")
            import traceback
            traceback.print_exc()
            return 1  # Default to malware on error
