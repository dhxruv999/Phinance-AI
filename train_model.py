"""
Improved Phishing URL Detection Model Training
Focuses on high precision to reduce false positives on legitimate sites
No hardcoded whitelist - model learns to identify legitimate sites accurately
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier, VotingClassifier
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, precision_score, recall_score, f1_score
import joblib
import json
import warnings
warnings.filterwarnings('ignore')

# Try to import XGBoost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except:
    XGBOOST_AVAILABLE = False
    print("Note: XGBoost not available. Will use other models.")

print("=" * 70)
print("Advanced Phishing URL Detection Model Training")
print("Testing Multiple Models with Hyperparameter Optimization")
print("=" * 70)

# Step 1: Load datasets
print("\n[1/6] Loading datasets...")
mendeley_df = pd.read_csv('Model Training DataSets/Mendeley Dataset.csv')
uci_df = pd.read_csv('Model Training DataSets/UCI PhiUSIIL_Phishing_URL UCI DataSet.csv')

print(f"Mendeley dataset shape: {mendeley_df.shape}")
print(f"UCI dataset shape: {uci_df.shape}")

# Step 2: Standardize labels
print("\n[2/6] Standardizing labels...")
mendeley_df['label'] = mendeley_df['Type'].copy()
mendeley_df = mendeley_df.drop('Type', axis=1)

# Invert UCI labels: 0->1 (phishing), 1->0 (legitimate)
uci_df['label'] = 1 - uci_df['label']

print(f"Mendeley label distribution:\n{mendeley_df['label'].value_counts()}")
print(f"\nUCI label distribution:\n{uci_df['label'].value_counts()}")

# Step 3: Select URL-based features
print("\n[3/6] Selecting URL-based features...")
mendeley_features = mendeley_df.drop('label', axis=1).columns.tolist()
print(f"Mendeley has {len(mendeley_features)} URL features")

# Prepare datasets
mendeley_X = mendeley_df[mendeley_features].copy()
mendeley_y = mendeley_df['label'].copy()

# Prepare UCI data - map features
uci_X = pd.DataFrame()
for feature in mendeley_features:
    found = False
    uci_numeric_cols = uci_df.select_dtypes(include=[np.number]).columns.tolist()
    if 'label' in uci_numeric_cols:
        uci_numeric_cols.remove('label')
    
    for uf in uci_numeric_cols:
        if feature.lower() == uf.lower() or feature.lower().replace('_', '') == uf.lower().replace('_', ''):
            uci_X[feature] = uci_df[uf]
            found = True
            break
    
    # Try common mappings
    if not found:
        if feature == 'url_length' and 'URLLength' in uci_df.columns:
            uci_X[feature] = uci_df['URLLength']
            found = True
        elif feature == 'domain_length' and 'DomainLength' in uci_df.columns:
            uci_X[feature] = uci_df['DomainLength']
            found = True
        elif feature == 'number_of_subdomains' and 'NoOfSubDomain' in uci_df.columns:
            uci_X[feature] = uci_df['NoOfSubDomain']
            found = True
        elif feature == 'number_of_equal_in_url' and 'NoOfEqualsInURL' in uci_df.columns:
            uci_X[feature] = uci_df['NoOfEqualsInURL']
            found = True
        elif feature == 'number_of_questionmark_in_url' and 'NoOfQMarkInURL' in uci_df.columns:
            uci_X[feature] = uci_df['NoOfQMarkInURL']
            found = True
        elif feature == 'number_of_digits_in_url' and 'NoOfDegitsInURL' in uci_df.columns:
            uci_X[feature] = uci_df['NoOfDegitsInURL']
            found = True
    
    if not found:
        uci_X[feature] = 0

uci_X = uci_X[mendeley_features]

# Combine datasets
X_combined = pd.concat([mendeley_X, uci_X], ignore_index=True)
y_combined = pd.concat([mendeley_y, uci_df['label']], ignore_index=True)

print(f"Combined dataset shape: {X_combined.shape}")
print(f"Label distribution:\n{y_combined.value_counts()}")

# Handle NaN values
X_combined = X_combined.fillna(0)

# Step 4: Train-test split
print("\n[4/6] Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(
    X_combined, y_combined, test_size=0.2, random_state=42, stratify=y_combined
)

print(f"Training set: {X_train.shape[0]} samples")
print(f"Test set: {X_test.shape[0]} samples")

# Step 5: Train multiple models with optimized parameters
print("\n[5/6] Training and evaluating multiple models...")
print("=" * 70)

models = {}
results = {}

# Model 1: Random Forest (Optimized for precision)
print("\n1. Training Random Forest (Precision-focused)...")
rf_model = RandomForestClassifier(
    n_estimators=600,
    max_depth=35,
    min_samples_split=4,
    min_samples_leaf=2,
    max_features='sqrt',
    random_state=42,
    n_jobs=-1,
    class_weight={0: 1.0, 1: 0.85}  # Slightly favor legitimate to reduce false positives
)
rf_model.fit(X_train, y_train)
rf_pred = rf_model.predict(X_test)
rf_pred_proba = rf_model.predict_proba(X_test)[:, 1]

results['RandomForest'] = {
    'model': rf_model,
    'accuracy': accuracy_score(y_test, rf_pred),
    'roc_auc': roc_auc_score(y_test, rf_pred_proba),
    'precision': precision_score(y_test, rf_pred),
    'recall': recall_score(y_test, rf_pred),
    'f1': f1_score(y_test, rf_pred)
}
print(f"   Accuracy: {results['RandomForest']['accuracy']:.4f}")
print(f"   Precision: {results['RandomForest']['precision']:.4f}")
print(f"   Recall: {results['RandomForest']['recall']:.4f}")
print(f"   F1-Score: {results['RandomForest']['f1']:.4f}")

# Model 2: Gradient Boosting (Optimized for precision)
print("\n2. Training Gradient Boosting (Precision-focused)...")
gb_model = GradientBoostingClassifier(
    n_estimators=500,
    max_depth=18,
    learning_rate=0.02,
    subsample=0.85,
    max_features='sqrt',
    random_state=42
)
gb_model.fit(X_train, y_train)
gb_pred = gb_model.predict(X_test)
gb_pred_proba = gb_model.predict_proba(X_test)[:, 1]

results['GradientBoosting'] = {
    'model': gb_model,
    'accuracy': accuracy_score(y_test, gb_pred),
    'roc_auc': roc_auc_score(y_test, gb_pred_proba),
    'precision': precision_score(y_test, gb_pred),
    'recall': recall_score(y_test, gb_pred),
    'f1': f1_score(y_test, gb_pred)
}
print(f"   Accuracy: {results['GradientBoosting']['accuracy']:.4f}")
print(f"   Precision: {results['GradientBoosting']['precision']:.4f}")
print(f"   Recall: {results['GradientBoosting']['recall']:.4f}")
print(f"   F1-Score: {results['GradientBoosting']['f1']:.4f}")

# Model 3: AdaBoost (Optimized)
print("\n3. Training AdaBoost (Optimized)...")
ada_model = AdaBoostClassifier(
    n_estimators=300,
    learning_rate=0.1,
    random_state=42
)
ada_model.fit(X_train, y_train)
ada_pred = ada_model.predict(X_test)
ada_pred_proba = ada_model.predict_proba(X_test)[:, 1]

results['AdaBoost'] = {
    'model': ada_model,
    'accuracy': accuracy_score(y_test, ada_pred),
    'roc_auc': roc_auc_score(y_test, ada_pred_proba),
    'precision': precision_score(y_test, ada_pred),
    'recall': recall_score(y_test, ada_pred),
    'f1': f1_score(y_test, ada_pred)
}
print(f"   Accuracy: {results['AdaBoost']['accuracy']:.4f}")
print(f"   Precision: {results['AdaBoost']['precision']:.4f}")
print(f"   Recall: {results['AdaBoost']['recall']:.4f}")
print(f"   F1-Score: {results['AdaBoost']['f1']:.4f}")

# Model 4: XGBoost (if available)
if XGBOOST_AVAILABLE:
    print("\n4. Training XGBoost (Optimized)...")
    try:
        xgb_model = xgb.XGBClassifier(
            n_estimators=500,
            max_depth=18,
            learning_rate=0.02,
            subsample=0.85,
            colsample_bytree=0.85,
            random_state=42,
            eval_metric='logloss',
            use_label_encoder=False,
            scale_pos_weight=0.85  # Reduce false positives
        )
        xgb_model.fit(X_train, y_train)
        xgb_pred = xgb_model.predict(X_test)
        xgb_pred_proba = xgb_model.predict_proba(X_test)[:, 1]

        results['XGBoost'] = {
            'model': xgb_model,
            'accuracy': accuracy_score(y_test, xgb_pred),
            'roc_auc': roc_auc_score(y_test, xgb_pred_proba),
            'precision': precision_score(y_test, xgb_pred),
            'recall': recall_score(y_test, xgb_pred),
            'f1': f1_score(y_test, xgb_pred)
        }
        print(f"   Accuracy: {results['XGBoost']['accuracy']:.4f}")
        print(f"   Precision: {results['XGBoost']['precision']:.4f}")
        print(f"   Recall: {results['XGBoost']['recall']:.4f}")
        print(f"   F1-Score: {results['XGBoost']['f1']:.4f}")
    except Exception as e:
        print(f"   XGBoost training failed: {e}")

# Model 5: Ensemble (Voting Classifier) - combines multiple models
print("\n5. Training Ensemble Model (Voting Classifier)...")
ensemble_models = []
if 'RandomForest' in results:
    ensemble_models.append(('rf', results['RandomForest']['model']))
if 'GradientBoosting' in results:
    ensemble_models.append(('gb', results['GradientBoosting']['model']))
if 'XGBoost' in results:
    ensemble_models.append(('xgb', results['XGBoost']['model']))

if len(ensemble_models) >= 2:
    ensemble = VotingClassifier(estimators=ensemble_models, voting='soft')
    ensemble.fit(X_train, y_train)
    ensemble_pred = ensemble.predict(X_test)
    ensemble_pred_proba = ensemble.predict_proba(X_test)[:, 1]

    results['Ensemble'] = {
        'model': ensemble,
        'accuracy': accuracy_score(y_test, ensemble_pred),
        'roc_auc': roc_auc_score(y_test, ensemble_pred_proba),
        'precision': precision_score(y_test, ensemble_pred),
        'recall': recall_score(y_test, ensemble_pred),
        'f1': f1_score(y_test, ensemble_pred)
    }
    print(f"   Accuracy: {results['Ensemble']['accuracy']:.4f}")
    print(f"   Precision: {results['Ensemble']['precision']:.4f}")
    print(f"   Recall: {results['Ensemble']['recall']:.4f}")
    print(f"   F1-Score: {results['Ensemble']['f1']:.4f}")

# Step 6: Select best model
print("\n" + "=" * 70)
print("[6/6] Model Comparison and Selection")
print("=" * 70)

# Select best model based on precision (reduce false positives), then accuracy and F1-score
# Prioritize precision to avoid flagging legitimate sites as phishing
best_model_name = max(results.keys(), key=lambda k: (results[k]['precision'], results[k]['accuracy'], results[k]['f1']))
best_model = results[best_model_name]['model']
best_results = results[best_model_name]

print("\nModel Comparison:")
print(f"{'Model':<20} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
print("-" * 70)
for name, metrics in results.items():
    marker = " <-- BEST" if name == best_model_name else ""
    print(f"{name:<20} {metrics['accuracy']:<12.4f} {metrics['precision']:<12.4f} {metrics['recall']:<12.4f} {metrics['f1']:<12.4f}{marker}")

print(f"\n✓ Best Model: {best_model_name}")
print(f"  Accuracy: {best_results['accuracy']:.4f} ({best_results['accuracy']*100:.2f}%)")
print(f"  ROC-AUC: {best_results['roc_auc']:.4f}")
print(f"  Precision: {best_results['precision']:.4f}")
print(f"  Recall: {best_results['recall']:.4f}")
print(f"  F1-Score: {best_results['f1']:.4f}")

# Detailed classification report
print("\nDetailed Classification Report:")
best_pred = best_model.predict(X_test)
print(classification_report(y_test, best_pred, target_names=['Legitimate', 'Phishing']))

# Save the best model
print("\n" + "=" * 70)
print("Saving best model...")

joblib.dump(best_model, 'phishing_detection_model.pkl')
joblib.dump(mendeley_features, 'model_features.pkl')

model_info = {
    'model_type': best_model_name,
    'accuracy': float(best_results['accuracy']),
    'roc_auc': float(best_results['roc_auc']),
    'precision': float(best_results['precision']),
    'recall': float(best_results['recall']),
    'f1_score': float(best_results['f1']),
    'n_features': len(mendeley_features),
    'n_train_samples': len(X_train),
    'n_test_samples': len(X_test),
    'features': mendeley_features,
    'all_model_results': {k: {m: float(v) for m, v in metrics.items() if m != 'model'} for k, metrics in results.items()},
    'note': 'Trained with focus on precision to reduce false positives. No whitelist required - model learns to identify legitimate sites accurately.'
}

with open('model_info.json', 'w') as f:
    json.dump(model_info, f, indent=2)

print("✓ Model saved as 'phishing_detection_model.pkl'")
print("✓ Features saved as 'model_features.pkl'")
print("✓ Model info saved as 'model_info.json'")

# Feature importance
print("\n" + "=" * 70)
print("Top 20 Most Important Features:")
if hasattr(best_model, 'feature_importances_'):
    feature_importance = pd.DataFrame({
        'feature': mendeley_features,
        'importance': best_model.feature_importances_
    }).sort_values('importance', ascending=False)
    print(feature_importance.head(20).to_string(index=False))

print("\n" + "=" * 70)
print("Training completed successfully!")
print("=" * 70)

