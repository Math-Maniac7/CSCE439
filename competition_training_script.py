#!/usr/bin/env python3
"""
Training script optimized for competition requirements
Focuses on achieving FPR ≤ 1% and TPR ≥ 95%
"""

import os
import sys
import numpy as np
import pandas as pd
import pickle
import time
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score, roc_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
import matplotlib.pyplot as plt

# Add path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from final_optimized_model import OptimizedNFSModel, FastPEAttributeExtractor
from nfs_model import JSONAttributeExtractor  # Your existing extractor

def load_training_data_from_jsonl(file_paths, max_samples_per_file=None):
    """Load training data from JSONL files (your existing format)"""
    print("Loading training data from JSONL files...")
    
    all_attributes = []
    
    for file_path in file_paths:
        if not os.path.exists(file_path):
            print(f"Warning: File not found: {file_path}")
            continue
            
        print(f"Processing {file_path}...")
        
        with open(file_path, 'r') as f:
            lines = f.readlines()
            
        if max_samples_per_file:
            lines = lines[:max_samples_per_file]
        
        for i, line in enumerate(lines):
            try:
                extractor = JSONAttributeExtractor(line.strip())
                attributes = extractor.extract()
                all_attributes.append(attributes)
                
                if (i + 1) % 1000 == 0:
                    print(f"  Processed {i + 1} samples from {file_path}")
                    
            except Exception as e:
                print(f"Error processing line {i} in {file_path}: {e}")
                continue
    
    if not all_attributes:
        raise ValueError("No valid training data found!")
    
    df = pd.DataFrame(all_attributes)
    # Filter to only include labeled samples
    df = df[(df["label"] == 1) | (df["label"] == 0)]
    
    print(f"Loaded {len(df)} total samples")
    print(f"Malware samples: {np.sum(df['label'] == 1)}")
    print(f"Benign samples: {np.sum(df['label'] == 0)}")
    
    return df

def optimize_threshold_for_competition(model, X_val, y_val):
    """Find optimal threshold to meet competition requirements"""
    print("\nOptimizing threshold for competition requirements...")
    
    # Get prediction probabilities
    y_proba = model.predict_proba(X_val)[:, 1]
    
    # Test thresholds from very conservative to moderate
    thresholds = np.arange(0.01, 0.5, 0.01)
    results = []
    
    print("Threshold\tTPR\tFPR\tF1\tScore")
    print("-" * 45)
    
    best_threshold = 0.5
    best_score = -1
    
    for threshold in thresholds:
        y_pred = (y_proba >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_val, y_pred).ravel()
        
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0  # Sensitivity/Recall
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
        f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0
        
        # Competition scoring: prioritize meeting constraints
        score = 0
        if tpr >= 0.95 and fpr <= 0.01:
            score = 100 + f1 * 10  # Perfect score + bonus for F1
        elif tpr >= 0.95:
            score = 50 - (fpr - 0.01) * 1000  # Penalize high FPR heavily
        elif fpr <= 0.01:
            score = 25 + tpr * 75  # Partial credit for low FPR
        else:
            score = tpr * 25 - fpr * 25  # Basic scoring
        
        results.append({
            'threshold': threshold,
            'tpr': tpr,
            'fpr': fpr,
            'f1': f1,
            'score': score
        })
        
        if score > best_score:
            best_score = score
            best_threshold = threshold
        
        if threshold % 0.05 < 0.01:  # Print every 5th threshold
            print(f"{threshold:.2f}\t\t{tpr:.3f}\t{fpr:.3f}\t{f1:.3f}\t{score:.1f}")
    
    print(f"\nBest threshold: {best_threshold:.3f} (Score: {best_score:.1f})")
    
    # Final evaluation with best threshold
    y_pred_final = (y_proba >= best_threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, y_pred_final).ravel()
    
    final_tpr = tp / (tp + fn)
    final_fpr = fp / (fp + tn)
    final_f1 = 2 * tp / (2 * tp + fp + fn)
    
    print(f"\nFinal Performance with threshold {best_threshold:.3f}:")
    print(f"TPR (Sensitivity): {final_tpr:.4f} {'✓' if final_tpr >= 0.95 else '✗'} (≥95%)")
    print(f"FPR: {final_fpr:.4f} {'✓' if final_fpr <= 0.01 else '✗'} (≤1%)")
    print(f"F1 Score: {final_f1:.4f}")
    
    return best_threshold, results

def train_competition_model(train_files, model_type='random_forest', max_samples=None):
    """Train model optimized for competition"""
    
    # Load training data
    df_train = load_training_data_from_jsonl(train_files, max_samples)
    
    # Split data
    X = df_train.drop('label', axis=1)
    y = df_train['label']
    
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Validation set: {len(X_val)} samples")
    
    # Initialize model
    if model_type == 'random_forest':
        base_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
    elif model_type == 'logistic_regression':
        base_classifier = LogisticRegression(
            random_state=42,
            max_iter=1000,
            C=1.0,
            class_weight='balanced'
        )
    else:
        raise ValueError(f"Unsupported model type: {model_type}")
    
    model = OptimizedNFSModel(classifier=base_classifier)
    
    # Train model
    print(f"\nTraining {model_type} model...")
    start_time = time.time()
    
    train_data_with_labels = X_train.copy()
    train_data_with_labels['label'] = y_train
    
    model.fit(train_data_with_labels)
    
    training_time = time.time() - start_time
    print(f"Training completed in {training_time:.2f} seconds")
    
    # Evaluate on validation set
    print("\n" + "="*50)
    print("MODEL EVALUATION")
    print("="*50)
    
    # Basic predictions for overall metrics
    val_data_with_labels = X_val.copy()
    val_data_with_labels['label'] = y_val  # Temporary for compatibility
    
    y_pred_basic = model.predict(val_data_with_labels.drop('label', axis=1))
    
    print("\nBasic Classification Report:")
    print(classification_report(y_val, y_pred_basic, target_names=['Benign', 'Malware']))
    
    # Optimize threshold for competition
    optimal_threshold, threshold_results = optimize_threshold_for_competition(
        model, X_val, y_val
    )
    
    return model, optimal_threshold, {
        'training_time': training_time,
        'validation_performance': threshold_results,
        'model_type': model_type
    }

def main():
    """Main training function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Train competition malware detector')
    parser.add_argument('--train_files', nargs='+', required=True,
                       help='JSONL training files to use')
    parser.add_argument('--model_type', choices=['random_forest', 'logistic_regression'],
                       default='random_forest', help='Type of classifier')
    parser.add_argument('--output_path', default='models/competition_model.pkl',
                       help='Output path for trained model')
    parser.add_argument('--max_samples', type=int, default=None,
                       help='Max samples per file (for testing)')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(os.path.dirname(args.output_path), exist_ok=True)
    
    try:
        # Train model
        model, optimal_threshold, training_info = train_competition_model(
            args.train_files, args.model_type, args.max_samples
        )
        
        # Save model with metadata
        model_data = {
            'model': model,
            'optimal_threshold': optimal_threshold,
            'training_info': training_info,
            'competition_requirements': {
                'max_memory_gb': 1,
                'max_response_time_seconds': 5,
                'max_fpr': 0.01,
                'min_tpr': 0.95
            }
        }
        
        with open(args.output_path, 'wb') as f:
            pickle.dump(model_data, f, protocol=pickle.HIGHEST_PROTOCOL)
        
        print(f"\nModel saved to {args.output_path}")
        print(f"Optimal threshold: {optimal_threshold:.4f}")
        print("\nTo use this model, update your prediction threshold in the Flask app.")
        
    except Exception as e:
        print(f"Training failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())