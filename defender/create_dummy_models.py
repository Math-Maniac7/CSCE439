#!/usr/bin/env python3
"""
Create dummy model files for the PE Malware Defender
This creates the pickle files that NFSModel expects
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MinMaxScaler

def create_directories():
    """Create necessary directories"""
    dirs = [
        "defender/models",
        "defender/models/nfs_behemot"
    ]
    
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")

def create_main_classifier():
    """Create a simple Random Forest classifier"""
    print("Creating main classifier...")
    
    clf = RandomForestClassifier(n_estimators=10, random_state=42)
    
    # Generate dummy training data
    X = np.random.random((100, 50))
    y = np.random.randint(0, 2, 100)
    
    clf.fit(X, y)
    
    # Save the classifier
    model_path = "defender/models/nfs_full.pickle"
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    
    print(f"Created: {model_path}")

def create_tfidf_extractor():
    """Create a TF-IDF vectorizer"""
    print("Creating TF-IDF extractor...")
    
    tfidf = TfidfVectorizer(max_features=100)
    
    # Dummy text data
    dummy_texts = [
        "kernel32.dll user32.dll",
        "CreateFile ReadFile WriteFile",
        "RegOpenKey RegSetValue"
    ] * 30
    
    tfidf.fit(dummy_texts)
    
    extractor_path = "defender/models/nfs_behemot/nfs_extractor_tfidf.pkl"
    with open(extractor_path, "wb") as f:
        pickle.dump(tfidf, f)
    
    print(f"Created: {extractor_path}")

def create_scaler():
    """Create a MinMax scaler"""
    print("Creating MinMax scaler...")
    
    scaler = MinMaxScaler()
    dummy_data = np.random.random((100, 150))
    scaler.fit(dummy_data)
    
    scaler_path = "defender/models/nfs_behemot/nfs_scaler_minmax.pkl"
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    
    print(f"Created: {scaler_path}")

def main():
    print("Creating dummy model files...")
    
    create_directories()
    create_main_classifier()
    create_tfidf_extractor()
    create_scaler()
    
    print("Done! Dummy models created.")

if __name__ == "__main__":
    main()