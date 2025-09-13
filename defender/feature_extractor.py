import os
import re
import lief
import math
import numpy as np
import pandas as pd
import pickle
from collections import Counter
import hashlib

class OptimizedPEFeatureExtractor:
    """
    Optimized PE feature extractor for malware detection
    Focus on speed and memory efficiency while maintaining high accuracy
    """
    
    def __init__(self):
        self.feature_cache = {}
        
    def extract_features(self, bytez):
        """
        Extract features from PE file bytes
        Returns numpy array of features
        """
        # Quick hash check for caching
        file_hash = hashlib.md5(bytez).hexdigest()
        if file_hash in self.feature_cache:
            return self.feature_cache[file_hash]
            
        features = []
        
        try:
            # Parse PE with LIEF (faster than pefile for our needs)
            binary = lief.PE.parse(list(bytez))
            if not binary:
                return self._get_default_features()
            
            # Basic file properties
            features.extend(self._extract_basic_features(bytez, binary))
            
            # Header features
            features.extend(self._extract_header_features(binary))
            
            # Section features  
            features.extend(self._extract_section_features(binary))
            
            # Import/Export features
            features.extend(self._extract_import_export_features(binary))
            
            # String-based features
            features.extend(self._extract_string_features(bytez))
            
            # Entropy-based features
            features.extend(self._extract_entropy_features(bytez))
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return self._get_default_features()
        
        feature_array = np.array(features, dtype=np.float32)
        
        # Cache result
        self.feature_cache[file_hash] = feature_array
        
        return feature_array
    
    def _extract_basic_features(self, bytez, binary):
        """Extract basic file features"""
        return [
            len(bytez),  # file size
            binary.virtual_size if hasattr(binary, 'virtual_size') else 0,
            int(binary.has_debug) if hasattr(binary, 'has_debug') else 0,
            int(binary.has_relocations) if hasattr(binary, 'has_relocations') else 0,
            int(binary.has_resources) if hasattr(binary, 'has_resources') else 0,
            int(binary.has_signature) if hasattr(binary, 'has_signature') else 0,
            int(binary.has_tls) if hasattr(binary, 'has_tls') else 0,
            len(binary.imports) if hasattr(binary, 'imports') else 0,
            len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0,
        ]
    
    def _extract_header_features(self, binary):
        """Extract header-based features"""
        try:
            header = binary.header
            optional_header = binary.optional_header
            
            return [
                header.time_date_stamps if hasattr(header, 'time_date_stamps') else 0,
                header.numberof_sections if hasattr(header, 'numberof_sections') else 0,
                header.numberof_symbols if hasattr(header, 'numberof_symbols') else 0,
                int(header.characteristics) if hasattr(header, 'characteristics') else 0,
                optional_header.baseof_code if hasattr(optional_header, 'baseof_code') else 0,
                getattr(optional_header, 'baseof_data', 0),
                optional_header.imagebase if hasattr(optional_header, 'imagebase') else 0,
                optional_header.file_alignment if hasattr(optional_header, 'file_alignment') else 0,
                optional_header.sizeof_code if hasattr(optional_header, 'sizeof_code') else 0,
                optional_header.sizeof_headers if hasattr(optional_header, 'sizeof_headers') else 0,
                optional_header.sizeof_image if hasattr(optional_header, 'sizeof_image') else 0,
                int(optional_header.dll_characteristics) if hasattr(optional_header, 'dll_characteristics') else 0,
                int(optional_header.magic) if hasattr(optional_header, 'magic') else 0,
            ]
        except:
            return [0] * 13
    
    def _extract_section_features(self, binary):
        """Extract section-based features"""
        try:
            sections = binary.sections
            if not sections:
                return [0] * 8
                
            # Aggregate section statistics
            total_raw_size = sum(s.size for s in sections)
            total_virtual_size = sum(s.virtual_size for s in sections)
            executable_sections = sum(1 for s in sections if s.characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
            writable_sections = sum(1 for s in sections if s.characteristics & 0x80000000)   # IMAGE_SCN_MEM_WRITE
            
            # Calculate entropy statistics for sections
            section_entropies = []
            for section in sections:
                try:
                    content = section.content
                    if content and len(content) > 0:
                        section_entropies.append(self._calculate_entropy(content))
                except:
                    continue
            
            avg_entropy = np.mean(section_entropies) if section_entropies else 0
            max_entropy = np.max(section_entropies) if section_entropies else 0
            
            return [
                len(sections),
                total_raw_size,
                total_virtual_size,
                executable_sections,
                writable_sections,
                total_virtual_size - total_raw_size,  # virtual vs raw size difference
                avg_entropy,
                max_entropy
            ]
        except:
            return [0] * 8
    
    def _extract_import_export_features(self, binary):
        """Extract import/export features"""
        features = []
        
        # Import features
        try:
            if binary.has_imports:
                # Count unique libraries and functions
                libraries = set()
                functions = []
                suspicious_apis = 0
                
                # Suspicious API patterns
                suspicious_patterns = [
                    'createfile', 'writefile', 'readfile', 'deletepart', 'copyfile',
                    'regopenkeyex', 'regsetvalueex', 'regdeletekey',
                    'createprocess', 'createthread', 'createremotethread',
                    'virtualalloc', 'virtualprotect', 'getprocaddress',
                    'loadlibrary', 'winexec', 'shellexecute',
                    'internetopen', 'internetconnect', 'httpopen',
                    'cryptacquirecontext', 'cryptencrypt', 'cryptdecrypt'
                ]
                
                for imp in binary.imports:
                    if hasattr(imp, 'name') and imp.name:
                        libraries.add(imp.name.lower())
                    
                    if hasattr(imp, 'entries'):
                        for entry in imp.entries:
                            if hasattr(entry, 'name') and entry.name:
                                func_name = entry.name.lower()
                                functions.append(func_name)
                                
                                # Check for suspicious APIs
                                if any(pattern in func_name for pattern in suspicious_patterns):
                                    suspicious_apis += 1
                
                features.extend([
                    len(libraries),
                    len(functions),
                    len(set(functions)),  # unique functions
                    suspicious_apis,
                ])
            else:
                features.extend([0, 0, 0, 0])
        except:
            features.extend([0, 0, 0, 0])
        
        # Export features
        try:
            if binary.has_exports:
                exports = binary.exported_functions
                features.extend([
                    len(exports),
                    len([e for e in exports if hasattr(e, 'name') and e.name])
                ])
            else:
                features.extend([0, 0])
        except:
            features.extend([0, 0])
        
        return features
    
    def _extract_string_features(self, bytez):
        """Extract string-based features efficiently"""
        # Convert to lowercase for case-insensitive matching
        bytez_lower = bytez.lower()
        
        # Count occurrences of suspicious patterns
        patterns = {
            b'c:\\\\': 0,  # file paths
            b'http': 0,    # URLs
            b'hkey_': 0,   # registry keys  
            b'mz': 0,      # PE headers
            b'kernel32': 0,
            b'ntdll': 0,
            b'wininet': 0,
            b'user32': 0,
            b'shell32': 0,
            b'advapi32': 0,
        }
        
        for pattern in patterns:
            patterns[pattern] = bytez_lower.count(pattern)
        
        # Count printable strings (simplified)
        printable_chars = sum(1 for b in bytez if 32 <= b <= 126)
        printable_ratio = printable_chars / len(bytez) if len(bytez) > 0 else 0
        
        return list(patterns.values()) + [printable_ratio]
    
    def _extract_entropy_features(self, bytez):
        """Extract entropy-based features"""
        if not bytez:
            return [0, 0, 0]
            
        # Overall entropy
        overall_entropy = self._calculate_entropy(bytez)
        
        # Chunk-based entropy analysis
        chunk_size = min(1024, len(bytez) // 4)  # Adaptive chunk size
        chunk_entropies = []
        
        if chunk_size > 0:
            for i in range(0, len(bytez), chunk_size):
                chunk = bytez[i:i+chunk_size]
                if len(chunk) > 10:  # Skip tiny chunks
                    chunk_entropies.append(self._calculate_entropy(chunk))
        
        if chunk_entropies:
            avg_chunk_entropy = np.mean(chunk_entropies)
            max_chunk_entropy = np.max(chunk_entropies)
        else:
            avg_chunk_entropy = overall_entropy
            max_chunk_entropy = overall_entropy
        
        return [overall_entropy, avg_chunk_entropy, max_chunk_entropy]
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy efficiently"""
        if not data:
            return 0
            
        # Use numpy for faster computation
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8))
        probabilities = byte_counts[byte_counts > 0] / len(data)
        
        return -np.sum(probabilities * np.log2(probabilities))
    
    def _get_default_features(self):
        """Return default feature vector when parsing fails"""
        return np.zeros(50, dtype=np.float32)  # Adjust size based on total features
    
    def get_feature_count(self):
        """Return the total number of features extracted"""
        # Update this based on the actual number of features
        return (9 +    # basic features
                13 +   # header features  
                8 +    # section features
                6 +    # import/export features
                11 +   # string features
                3)     # entropy features = 50 total