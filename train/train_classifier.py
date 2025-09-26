import pandas as pd
import numpy as np
import pickle
import gc
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score, confusion_matrix

class SimpleEMBERModel:
    """Simple model for pre-processed EMBER features"""
    
    def __init__(self, classifier=RandomForestClassifier(
        n_estimators=50,        # Reduced from 100 to 50 trees
        max_depth=20,           # Limit tree depth to prevent overfitting and speed up
        max_features='sqrt',    # Use sqrt of features instead of all features
        n_jobs=-1,             # Use all CPU cores
        random_state=42,
        verbose=1              # Show progress
    )):
        self.classifier = classifier
        self.scaler = MinMaxScaler()
        
    def fit(self, X, y):
        """Train the model"""
        print("Training feature scaler...")
        X_scaled = self.scaler.fit_transform(X)
        
        print("Training classifier...")
        self.classifier.fit(X_scaled, y)
        
    def predict(self, X):
        """Make predictions"""
        X_scaled = self.scaler.transform(X)
        return self.classifier.predict(X_scaled)
    
    def predict_proba(self, X):
        """Get prediction probabilities"""
        X_scaled = self.scaler.transform(X)
        return self.classifier.predict_proba(X_scaled)

def load_ember_parquet_incrementally(file_paths, chunk_size=50000):
    """Load EMBER Parquet files incrementally"""
    
    all_features = []
    all_labels = []
    total_samples = 0
    
    for file_path in file_paths:
        print(f"\nProcessing {file_path}...")
        
        # Read parquet file
        df = pd.read_parquet(file_path)
        print(f"  File shape: {df.shape}")
        print(f"  Columns: {list(df.columns)[:10]}...")
        
        # Check if label column exists
        label_col = None
        possible_label_names = ['Label', 'label', 'y', 'target', 'class', 'malware']  # Added 'Label' (capital L)
        
        for col_name in possible_label_names:
            if col_name in df.columns:
                label_col = col_name
                print(f"  Found label column: {col_name}")
                break
        
        if label_col is None:
            print(f"  WARNING: No label column found in {file_path}")
            print(f"  Available columns: {list(df.columns)}")
            # If no labels, assume this is training data and try to infer
            # For now, we'll skip files without labels
            continue
            
        # Get features (all columns except label)
        feature_cols = [col for col in df.columns if col != label_col]
        print(f"  Using {len(feature_cols)} features")
        
        # Process in chunks to manage memory
        for start_idx in range(0, len(df), chunk_size):
            end_idx = min(start_idx + chunk_size, len(df))
            chunk = df.iloc[start_idx:end_idx]
            
            # Get features and labels
            X_chunk = chunk[feature_cols].values
            y_chunk = chunk[label_col].values
            
            # Filter valid labels (0 or 1)
            valid_mask = (y_chunk == 0) | (y_chunk == 1)
            X_chunk = X_chunk[valid_mask]
            y_chunk = y_chunk[valid_mask]
            
            if len(X_chunk) > 0:
                all_features.append(X_chunk)
                all_labels.append(y_chunk)
                total_samples += len(X_chunk)
            
            print(f"    Processed chunk {start_idx}-{end_idx}, valid samples: {len(X_chunk)}")
            
        # Clean up
        del df
        gc.collect()
    
    if not all_features:
        raise ValueError("No valid data found! Check if label columns exist in your files.")
    
    # Concatenate all features and labels
    print("\nCombining all data...")
    X = np.vstack(all_features)
    y = np.concatenate(all_labels)
    
    print(f"Final dataset: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"Labels: {np.sum(y == 1)} malware, {np.sum(y == 0)} benign")
    
    return X, y

def train_ember_model(train_files, model_output_path="nfs_full.pickle", quick_test=False):
    """Train EMBER model on pre-processed features"""
    
    print("=== LOADING EMBER DATA ===")
    X, y = load_ember_parquet_incrementally(train_files)
    
    # Option for quick testing with smaller dataset
    if quick_test:
        print("=== QUICK TEST MODE: Using 50,000 samples ===")
        indices = np.random.choice(len(X), size=min(50000, len(X)), replace=False)
        X = X[indices]
        y = y[indices]
        print(f"Reduced dataset: {X.shape[0]} samples")
    
    print(f"\n=== TRAINING MODEL ===")
    print(f"Dataset size: {X.shape[0]} samples, {X.shape[1]} features")
    model = SimpleEMBERModel()
    model.fit(X, y)
    
    print(f"\n=== SAVING MODEL ===")
    with open(model_output_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"Model saved to: {model_output_path}")
    print(f"Training complete!")
    
    return model, X, y

def evaluate_model(model, X_test, y_test):
    """Evaluate model performance"""
    print("\n=== EVALUATING MODEL ===")
    
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]  # Probability of malware
    
    # Calculate metrics
    acc = accuracy_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    pre = precision_score(y_test, y_pred)
    f1s = f1_score(y_test, y_pred)
    
    print(f"Accuracy:  {acc:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"Precision: {pre:.4f}")
    print(f"F1 Score:  {f1s:.4f}")
    
    # Confusion matrix
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    print(f"\nConfusion Matrix:")
    print(f"True Negatives:  {tn}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    print(f"True Positives:  {tp}")
    
    # Rates
    fpr = fp/(fp+tn)
    fnr = fn/(tp+fn)
    print(f"\nFalse Positive Rate: {fpr:.4f}")
    print(f"False Negative Rate: {fnr:.4f}")

# Configuration
train_files = [
    "data/2017/train_ember_2017_v2_features.parquet",
    "data/2018/train_ember_2018_v2_features.parquet"
]

test_files = [
    "data/2017/test_ember_2017_v2_features.parquet",
    "data/2018/test_ember_2018_v2_features.parquet"
]

if __name__ == '__main__':
    print("=== EMBER PRE-PROCESSED FEATURES TRAINING ===")
    print(f"Training files: {len(train_files)}")
    
    # Train model - set quick_test=True for faster training with smaller dataset
    model, X_train, y_train = train_ember_model(
        train_files=train_files,
        model_output_path="nfs_full.pickle",
        quick_test=True  # Change to False for full dataset training
    )
    
    # Optional: Load and evaluate on test data
    try:
        print("\n=== LOADING TEST DATA ===")
        X_test, y_test = load_ember_parquet_incrementally(test_files)
        
        # Evaluate model
        evaluate_model(model, X_test, y_test)
        
    except Exception as e:
        print(f"Test evaluation failed: {e}")
        print("Model training completed successfully anyway!")
    
    print("\n=== TRAINING COMPLETE ===")
    print("Your nfs_full.pickle model is ready!")