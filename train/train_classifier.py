import pandas as pd
import numpy as np
import gc
import os
import gzip
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score, confusion_matrix

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
        possible_label_names = ['Label', 'label', 'y', 'target', 'class', 'malware']
        
        for col_name in possible_label_names:
            if col_name in df.columns:
                label_col = col_name
                print(f"  Found label column: {col_name}")
                break
        
        if label_col is None:
            print(f"  WARNING: No label column found in {file_path}")
            print(f"  Available columns: {list(df.columns)}")
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

def train_ember_lightgbm(train_files, model_output_path="ember_model.txt", quick_test=False):
    """Train EMBER model using LightGBM"""
    
    print("=== LOADING EMBER DATA ===")
    X, y = load_ember_parquet_incrementally(train_files)
    
    # Option for quick testing with smaller dataset
    if quick_test:
        print("=== QUICK TEST MODE: Using 50,000 samples ===")
        indices = np.random.choice(len(X), size=min(50000, len(X)), replace=False)
        X = X[indices]
        y = y[indices]
        print(f"Reduced dataset: {X.shape[0]} samples")
    
    # Split for validation
    print("\n=== SPLITTING DATA ===")
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Validation set: {X_val.shape[0]} samples")
    
    print(f"\n=== TRAINING LIGHTGBM MODEL ===")
    
    # Create LightGBM datasets
    train_data = lgb.Dataset(X_train, label=y_train)
    val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
    
    # Parameters optimized for EMBER (from their paper)
    params = {
        'boosting_type': 'gbdt',
        'objective': 'binary',
        'metric': ['binary_logloss', 'binary_error'],
        'num_leaves': 2048,
        'learning_rate': 0.05,
        'feature_fraction': 0.5,
        'bagging_fraction': 1.0,
        'bagging_freq': 0,
        'verbose': 1,
        'num_threads': -1
    }
    
    # Train
    print("Starting training...")
    model = lgb.train(
        params,
        train_data,
        num_boost_round=1000,
        valid_sets=[train_data, val_data],
        valid_names=['train', 'valid'],
        callbacks=[
            lgb.early_stopping(stopping_rounds=20),
            lgb.log_evaluation(period=10)
        ]
    )
    
    print(f"\n=== SAVING MODEL ===")
    # Save as text file
    model.save_model(model_output_path, num_iteration=model.best_iteration)
    print(f"Model saved to: {model_output_path}")
    
    # Compress it (required format for ember_model.py)
    gz_path = model_output_path + '.gz'
    with open(model_output_path, 'r') as f_in:
        with gzip.open(gz_path, 'wb') as f_out:
            f_out.write(f_in.read().encode('ascii'))
    
    print(f"Compressed model saved to: {gz_path}")
    print(f"Training complete!")
    
    return model, X_train, y_train, X_val, y_val

def evaluate_model(model, X, y):
    """Evaluate model performance"""
    y_pred_proba = model.predict(X)
    
    # Try different thresholds
    thresholds = [0.5, 0.8336]  # 0.8336 is the default in ember_model.py
    
    for thresh in thresholds:
        y_pred = (y_pred_proba >= thresh).astype(int)
        
        acc = accuracy_score(y, y_pred)
        f1 = f1_score(y, y_pred)
        recall = recall_score(y, y_pred)
        precision = precision_score(y, y_pred)
        
        print(f"\nThreshold: {thresh}")
        print(f"Accuracy:  {acc:.4f}")
        print(f"F1 Score:  {f1:.4f}")
        print(f"Recall:    {recall:.4f}")
        print(f"Precision: {precision:.4f}")
        
        cm = confusion_matrix(y, y_pred)
        print(f"Confusion Matrix:\n{cm}")

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
    print("=== EMBER LIGHTGBM TRAINING ===")
    print(f"Training files: {train_files}")
    
    # Train model - set quick_test=True for faster training with smaller dataset
    model, X_train, y_train, X_val, y_val = train_ember_lightgbm(
        train_files=train_files,
        model_output_path="../defender/defender/models/ember_model.txt",
        quick_test=True  # Change to False for full dataset training
    )
    
    # Evaluate on validation set
    print("\n=== VALIDATION SET EVALUATION ===")
    evaluate_model(model, X_val, y_val)
    
    # Optional: Load and evaluate on test data
    try:
        print("\n=== LOADING TEST DATA ===")
        X_test, y_test = load_ember_parquet_incrementally(test_files)
        
        # Evaluate model
        print("\n=== TEST SET EVALUATION ===")
        evaluate_model(model, X_test, y_test)
        
    except Exception as e:
        print(f"Test evaluation failed: {e}")
        print("Model training completed successfully anyway!")
    
    print("\n=== TRAINING COMPLETE ===")
    print("Your ember_model.txt.gz is ready!")
    print("\nNext steps:")
    print("1. Update Dockerfile: ENV DF_MODEL_NAME='ember'")
    print("2. Rebuild Docker: docker build -t malware-defense .")
    print("3. Run: docker run --memory=1g -p 8080:8080 malware-defense")
