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
        except Exception as e:
            print(f"Error parsing PE with LIEF: {e}")
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
            # Return minimal attributes if parsing failed
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
            self.attributes.update({
                "entropy": self.extract_entropy()
            })

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

            # Get identify
            self.attributes.update({"identify": self.extract_identify()})

            return self.attributes
            
        except Exception as e:
            print(f"Error extracting attributes: {e}")
            return self._get_minimal_attributes()
    
    def _get_minimal_attributes(self):
        """Return minimal attributes when parsing fails"""
        return {
            "size": len(self.bytez),
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
            "machine": "0",
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
            "magic": "0",
            "PE_TYPE": 0,
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
            "subsystem": "0",
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


class NeedForSpeedModel:
    """NFS model with feature extraction and classification"""
    
    # numerical attributes
    NUMERICAL_ATTRIBUTES = [
        'string_paths', 'string_urls', 'string_registry', 'string_MZ', 'size',
        'virtual_size', 'has_debug', 'imports', 'exports', 'has_relocations',
        'has_resources', 'has_signature', 'has_tls', 'symbols', 'timestamp', 
        'numberof_sections', 'major_image_version', 'minor_image_version', 
        'major_linker_version', 'minor_linker_version', 'major_operating_system_version',
        'minor_operating_system_version', 'major_subsystem_version', 
        'minor_subsystem_version', 'sizeof_code', 'sizeof_headers', 'sizeof_heap_commit'
    ]

    # categorical attributes
    CATEGORICAL_ATTRIBUTES = ['machine', 'magic']

    # textual attributes
    TEXTUAL_ATTRIBUTES = ['libraries', 'functions', 'exports_list',
                          'dll_characteristics_list', 'characteristics_list']

    def __init__(self, 
                categorical_extractor=OneHotEncoder(handle_unknown="ignore"), 
                textual_extractor=TfidfVectorizer(max_features=300),
                feature_scaler=MinMaxScaler(),
                classifier=RandomForestClassifier()):
        self.base_categorical_extractor = categorical_extractor
        self.base_textual_extractor = textual_extractor
        self.base_feature_scaler = feature_scaler
        self.base_classifier = classifier

    def _append_features(self, original_features, appended):
        if original_features:
            for l1, l2 in zip(original_features, appended):
                for i in l2:
                    l1.append(i)
            return original_features
        else:
            return appended.tolist()

    def predict(self, bytez):
        """Predict using the trained model"""
        try:
            pe_att_ext = PEAttributeExtractor(bytez)
            atts = pe_att_ext.extract()
            atts = pd.DataFrame([atts])
            
            # Extract features
            features = self._extract_features(atts)
            
            # Make prediction
            prediction = self.classifier.predict(features)[0]
            return int(prediction)
            
        except Exception as e:
            print(f"Error in prediction: {e}")
            return 1  # Default to malware if error


class NFSModel:
    """Simple NFSModel wrapper for compatibility"""
    
    def __init__(self, model_file):
        try:
            # Reset file pointer to beginning
            model_file.seek(0)
            
            # Try loading with different encodings
            try:
                self.clf = pickle.load(model_file)
            except UnicodeDecodeError:
                model_file.seek(0)
                self.clf = pickle.load(model_file, encoding='latin1')
            except:
                model_file.seek(0)
                self.clf = pickle.load(model_file, encoding='bytes')
                
        except Exception as e:
            print(f"Error loading pickle file: {e}")
            # Create a fallback dummy model
            from sklearn.ensemble import RandomForestClassifier
            self.clf = RandomForestClassifier(n_estimators=10, random_state=42)
            print("Using dummy classifier as fallback")

    def model_info(self):
        return {
            "name": "NFSModel",
            "version": "1.0",
            "type": "PE malware classifier",
            "description": "Random Forest-based PE file analyzer"
        }
    
    def predict(self, bytez: bytes) -> int:
        """Predict if PE file is malware (1) or benign (0)"""
        try:
            pe_att_ext = PEAttributeExtractor(bytez)
            atts = pe_att_ext.extract()
            atts = pd.DataFrame([atts])
            
            # Check if the model has the required features
            if hasattr(self.clf, 'predict_proba'):
                prob = self.clf.predict_proba(atts)[0]
                pred = int(prob[0] < 0.9)  # Threshold for classification
            else:
                pred = int(self.clf.predict(atts)[0])
                
            print(f"Prediction = {pred}")
            return pred
            
        except (lief.bad_format, lief.read_out_of_bound) as e:
            print(f"LIEF Error: {e}")
            return 1  # Default to malware
        except Exception as e:
            print(f"Error in prediction: {e}")
            return 0  # Default to benign for other errors