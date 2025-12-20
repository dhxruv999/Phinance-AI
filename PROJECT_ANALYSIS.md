# Phishing Detection System - Complete Project Analysis

## 📋 Project Overview

This is a **Machine Learning-based Phishing URL Detection System** that uses URL-based features to classify URLs as legitimate or phishing. The system combines multiple ML models with heuristic-based domain reputation analysis to achieve high accuracy while minimizing false positives.

---

## 🏗️ Project Architecture

### **System Components:**

1. **Model Training Pipeline** (`train_model.py`, `train_model.ipynb`)
2. **Prediction Engine** (`predict_phishing.py`)
3. **Testing Framework** (`test_banking_urls.py`)
4. **Web Interface** (Flask backend + HTML/CSS/JS frontend - if exists)

---

## 📁 File Structure & Analysis

### **1. Core Training Files**

#### **`train_model.py`** (338 lines)
**Purpose:** Train multiple ML models and select the best one based on precision

**Key Functionality:**
- **Data Loading:** Combines two datasets:
  - Mendeley Dataset (247,950 samples)
  - UCI PhiUSIIL Phishing URL Dataset (235,795 samples)
- **Label Standardization:** 
  - Mendeley: Uses `Type` column directly
  - UCI: Inverts labels (0→1 for phishing, 1→0 for legitimate)
- **Feature Mapping:** Maps UCI features to Mendeley feature set (41 features)
- **Model Training:** Trains 5 models:
  1. **Random Forest** (600 estimators, max_depth=35, class_weight tuned)
  2. **Gradient Boosting** (500 estimators, max_depth=18, learning_rate=0.02)
  3. **AdaBoost** (300 estimators, learning_rate=0.1)
  4. **XGBoost** (if available, 500 estimators, scale_pos_weight=0.85)
  5. **Ensemble** (Voting Classifier combining top models)
- **Model Selection:** Prioritizes **precision** (to reduce false positives), then accuracy, then F1-score
- **Output:** Saves best model, features list, and metadata

**Key Metrics:**
- Best Model: Gradient Boosting
- Accuracy: 95.88%
- Precision: 98.01%
- Recall: 92.83%
- F1-Score: 95.35%
- ROC-AUC: 98.10%

#### **`train_model.ipynb`**
**Purpose:** Interactive Jupyter notebook version of training script

**Features:**
- Step-by-step training with markdown explanations
- Interactive cell execution
- Better for experimentation and visualization
- Same functionality as `train_model.py`

---

### **2. Prediction Engine**

#### **`predict_phishing.py`** (609 lines)
**Purpose:** Main prediction script that combines ML model with heuristic analysis

**Key Functions:**

##### **`load_model()`** (lines 15-26)
- Loads trained model from `phishing_detection_model.pkl`
- Loads feature list from `model_features.pkl`
- Loads model metadata from `model_info.json`
- Handles missing file errors gracefully

##### **`calculate_entropy(text)`** (lines 28-38)
- Calculates Shannon entropy of a string
- Measures randomness/complexity
- Higher entropy = more random = potentially suspicious

##### **`has_repeated_digits(text)`** (lines 40-43)
- Detects repeated digit patterns (e.g., "111", "2222")
- Returns 1 if pattern found, 0 otherwise

##### **`extract_features_from_url(url)`** (lines 45-216)
**Extracts 41 URL-based features:**

**URL-Level Features:**
- `url_length`: Total URL length
- `number_of_dots_in_url`: Count of '.' characters
- `number_of_digits_in_url`: Count of digits
- `number_of_hyphens_in_url`: Count of '-' characters
- `number_of_underline_in_url`: Count of '_' characters
- `number_of_slash_in_url`: Count of '/' characters
- `number_of_questionmark_in_url`: Count of '?' characters
- `number_of_equal_in_url`: Count of '=' characters
- `number_of_at_in_url`: Count of '@' characters
- `number_of_dollar_in_url`: Count of '$' characters
- `number_of_exclamation_in_url`: Count of '!' characters
- `number_of_hashtag_in_url`: Count of '#' characters
- `number_of_percent_in_url`: Count of '%' characters
- `number_of_special_char_in_url`: Count of special characters
- `having_repeated_digits_in_url`: Binary flag for repeated digits
- `entropy_of_url`: Shannon entropy of entire URL

**Domain-Level Features:**
- `domain_length`: Length of domain name
- `number_of_dots_in_domain`: Count of dots in domain
- `number_of_hyphens_in_domain`: Count of hyphens in domain
- `having_special_characters_in_domain`: Binary flag
- `number_of_special_characters_in_domain`: Count
- `having_digits_in_domain`: Binary flag
- `number_of_digits_in_domain`: Count
- `having_repeated_digits_in_domain`: Binary flag
- `entropy_of_domain`: Shannon entropy of domain

**Subdomain Features:**
- `number_of_subdomains`: Count of subdomains
- `having_dot_in_subdomain`: Binary flag
- `having_hyphen_in_subdomain`: Binary flag
- `average_subdomain_length`: Average length of subdomains
- `average_number_of_dots_in_subdomain`: Average dot count
- `average_number_of_hyphens_in_subdomain`: Average hyphen count
- `having_special_characters_in_subdomain`: Binary flag
- `number_of_special_characters_in_subdomain`: Count
- `having_digits_in_subdomain`: Binary flag
- `number_of_digits_in_subdomain`: Count
- `having_repeated_digits_in_subdomain`: Binary flag

**Path/Query Features:**
- `having_path`: Binary flag (1 if path exists)
- `path_length`: Length of path
- `having_query`: Binary flag (1 if query string exists)
- `having_fragment`: Binary flag (1 if fragment exists)
- `having_anchor`: Binary flag (1 if '#' in URL)

##### **`get_domain_reputation_score(domain)`** (lines 218-385)
**Heuristic-based domain reputation analysis (NOT hardcoded whitelist)**

**Scoring Logic:**
1. **TLD Analysis:**
   - Legitimate TLDs: `.com`, `.org`, `.net`, `.edu`, `.gov`, `.co.uk`, `.co.in`, `.in`, etc.
   - Suspicious TLDs: `.xyz`, `.top`, `.online`, `.site`, `.website`, `.click`, `.link`, `.space`
   - Multi-part TLDs: Handles `.co.in`, `.co.uk` patterns

2. **Domain Length:**
   - Optimal: 5-30 characters (+0.10)
   - Acceptable: 30-40 characters (+0.05)
   - Suspicious: <3 or >50 characters (-0.15)

3. **Digit Ratio:**
   - >30% digits: -0.20
   - >50% digits: -0.30

4. **Hyphen Count:**
   - >2 hyphens: -0.20
   - 2 hyphens + suspicious words: -0.15
   - 0 hyphens: +0.05

5. **Keyword Analysis:**
   - **Financial Keywords:** `bank`, `banking`, `financial`, `finance`, `credit`, `capital`, `union`, `federal`, `state`, `national`, `central`, `reserve`
   - **Payment Keywords:** `pay`, `payment`, `paytm`, `phonepe`, `razorpay`, `stripe`, `paypal`, `wallet`, `upi`, `gateway`, `merchant`
   - **Suspicious Phishing Words:** `cashback`, `alert`, `verification`, `verify`, `reward`, `secure`, `login`, `update`, `claim`, `confirm`, `activate`, `suspended`, `locked`, `expired`, `urgent`, `warning`

6. **Combination Rules:**
   - Banking keyword + suspicious word: -0.40 (strong penalty)
   - Banking keyword + suspicious TLD: -0.50 (very strong penalty)
   - Banking keyword alone (with good TLD): +0.25 to +0.50
   - Payment keyword + suspicious word: -0.35
   - Payment keyword + suspicious TLD: -0.50

7. **Subdomain Analysis:**
   - Legitimate subdomains (`www`, `secure`, `online`, `portal`): +0.05
   - Suspicious subdomains (>1 hyphen or >20 chars): -0.10

**Returns:** Score between 0.0 (suspicious) and 1.0 (legitimate)

##### **`predict_url(url, model, features, threshold=0.75)`** (lines 387-521)
**Main prediction function combining ML model + heuristics**

**Process:**
1. Parse URL and extract domain
2. Check for suspicious query parameters (`session=`, `token=`, `verify=`, `confirm=`, `activate=`)
3. Extract 41 URL features
4. Get ML model prediction (probability)
5. Calculate domain reputation score
6. Adjust probability based on reputation:
   - **High reputation (≥0.75):** Blend model prediction with target legitimate probability
     - Reputation ≥0.85: Target 70-85% legitimate (90% for banking)
     - Reputation ≥0.75: Target 60-75% legitimate
     - Blend weight depends on model confidence (25-70% model, 30-75% target)
   - **Low reputation (<0.4):** Shift towards phishing (up to -0.20 adjustment)
   - **Medium reputation (0.4-0.6):** Moderate adjustment
7. Apply threshold (default 0.75 = 75% phishing probability required)
8. Return prediction (0=legitimate, 1=phishing), probabilities, and reputation score

**Key Feature:** Dynamic blending prevents false positives on legitimate banking sites without hardcoding whitelist

##### **`main()`** (lines 523-608)
**Command-line interface for predictions**

**Usage:**
```bash
python predict_phishing.py <URL>
```

**Output:**
- Model information
- Prediction result (LEGITIMATE/PHISHING)
- Confidence percentage
- Probability breakdown
- Domain reputation score
- Threshold information

---

### **3. Testing Framework**

#### **`test_banking_urls.py`** (215 lines)
**Purpose:** Test model on unseen dataset with detailed metrics

**Functionality:**
- Loads URLs from CSV file (`Unseen-phishing-dataset.csv`)
- Tests each URL using `predict_phishing.py` as subprocess
- Tracks:
  - True Positives (TP): Phishing correctly identified
  - True Negatives (TN): Legitimate correctly identified
  - False Positives (FP): Legitimate flagged as phishing
  - False Negatives (FN): Phishing flagged as legitimate
- Calculates metrics:
  - Accuracy: (TP + TN) / Total
  - Precision: TP / (TP + FP)
  - Recall: TP / (TP + FN)
  - F1-Score: 2 * (Precision * Recall) / (Precision + Recall)
- Displays confusion matrix
- Lists all false positives and false negatives
- Saves detailed results to `unseen_dataset_test_results.csv`

**Key Features:**
- Real-time progress tracking
- Per-URL result display
- Confidence statistics
- Detailed error reporting

---

### **4. Configuration Files**

#### **`requirements.txt`**
**Dependencies:**
- `pandas>=1.5.0` - Data manipulation
- `numpy>=1.23.0` - Numerical operations
- `scikit-learn>=1.2.0` - Machine learning
- `xgboost>=1.7.0` - XGBoost classifier (optional)
- `joblib>=1.2.0` - Model serialization
- `jupyter>=1.0.0` - Notebook support
- `matplotlib>=3.5.0` - Visualization

**Note:** Flask and Flask-CORS should be added for web interface

#### **`model_info.json`**
**Model Metadata:**
- Model type: GradientBoosting
- Performance metrics (accuracy, precision, recall, F1, ROC-AUC)
- Feature list (41 features)
- Training/test sample counts
- All model comparison results
- Notes about training approach

#### **`README.md`**
**Project Documentation:**
- Overview and performance metrics
- Installation instructions
- Usage examples
- Model comparison table
- Feature importance list
- Supported input types

---

### **5. Data Files**

#### **Training Datasets:**
- `Model Training DataSets/Mendeley Dataset.csv` (247,950 samples)
- `Model Training DataSets/UCI PhiUSIIL_Phishing_URL UCI DataSet.csv` (235,795 samples)

#### **Test Datasets:**
- `Unseen DataSets for testing/Unseen-phishing-dataset.csv` (unseen test data)
- `Unseen DataSets for testing/phishing-links-ACTIVE.txt` (789,169 phishing URLs)

#### **Model Artifacts:**
- `phishing_detection_model.pkl` - Trained Gradient Boosting model
- `model_features.pkl` - List of 41 feature names
- `model_info.json` - Model metadata

#### **Output Files:**
- `unseen_dataset_test_results.csv` - Detailed test results

---

## 🔄 Data Flow

### **Training Pipeline:**
```
Mendeley Dataset + UCI Dataset
    ↓
Label Standardization
    ↓
Feature Mapping & Extraction
    ↓
Data Combination (483,745 samples)
    ↓
Train-Test Split (80-20)
    ↓
Train Multiple Models (RF, GB, AdaBoost, XGBoost, Ensemble)
    ↓
Evaluate & Compare (Prioritize Precision)
    ↓
Select Best Model (Gradient Boosting)
    ↓
Save Model + Features + Metadata
```

### **Prediction Pipeline:**
```
User Input URL
    ↓
URL Validation & Normalization
    ↓
Extract 41 Features
    ↓
ML Model Prediction (Raw Probability)
    ↓
Calculate Domain Reputation Score (Heuristics)
    ↓
Blend Probabilities (Dynamic Adjustment)
    ↓
Apply Threshold (0.75)
    ↓
Return Prediction + Confidence + Reputation Score
```

---

## 🎯 Key Design Decisions

### **1. Precision-First Approach**
- Model selection prioritizes precision to minimize false positives
- Threshold set to 0.75 (requires 75% phishing probability)
- Class weights tuned to favor legitimate classification

### **2. Heuristic-Based Reputation (Not Whitelist)**
- No hardcoded domain whitelist
- Uses pattern matching and structural analysis
- Adaptable to new legitimate domains
- Reduces false positives on banking/financial sites

### **3. Dynamic Probability Blending**
- High-reputation domains get probability adjustment
- Blend weight depends on model confidence
- Prevents legitimate sites from being flagged incorrectly

### **4. Comprehensive Feature Set**
- 41 URL-based features
- No HTML content required (faster, more privacy-friendly)
- Features cover URL, domain, subdomain, path, query, entropy

### **5. Multi-Model Ensemble**
- Tests 5 different algorithms
- Selects best based on metrics
- Optional ensemble voting classifier

---

## 🔍 Feature Importance (Top 10)

1. **URL Length** - Phishing URLs often longer
2. **Number of Digits in URL** - Suspicious patterns
3. **Domain Length** - Legitimate domains typically shorter
4. **Average Subdomain Length** - Phishing uses long subdomains
5. **Number of Subdomains** - Multiple subdomains suspicious
6. **Number of Special Characters** - More special chars = suspicious
7. **Entropy of Domain** - Random domains suspicious
8. **Number of Slashes** - Path complexity indicator
9. **Entropy of URL** - Overall randomness measure
10. **Path Length** - Long paths can indicate phishing

---

## 🚀 Usage Examples

### **Training:**
```bash
# Option 1: Python script
python train_model.py

# Option 2: Jupyter notebook
jupyter notebook train_model.ipynb
```

### **Prediction:**
```bash
python predict_phishing.py https://www.example.com
python predict_phishing.py google.com
python predict_phishing.py 192.168.1.1
```

### **Testing:**
```bash
python test_banking_urls.py
```

---

## ⚠️ Known Limitations

1. **IP Addresses:** Often flagged as suspicious (by design for security)
2. **New Domains:** May be flagged if they don't match known patterns
3. **URL-Only Analysis:** Doesn't check HTML content or SSL certificates
4. **Language:** Primarily trained on English-language URLs
5. **False Positives:** Some legitimate sites with unusual patterns may be flagged

---

## 🔧 Potential Improvements

1. **Add Web Interface:** Flask backend + React/Vue frontend
2. **Real-time Updates:** Retrain model periodically with new data
3. **SSL Certificate Check:** Verify certificate validity
4. **WHOIS Lookup:** Check domain registration age
5. **Blacklist Integration:** Check against known phishing databases
6. **Multi-language Support:** Train on URLs from different languages
7. **API Endpoint:** RESTful API for integration
8. **Batch Processing:** Support for multiple URLs at once
9. **Confidence Intervals:** Provide uncertainty estimates
10. **Explainability:** Show which features contributed to decision

---

## 📊 Model Performance Summary

| Metric | Value |
|-------|-------|
| **Accuracy** | 95.88% |
| **Precision** | 98.01% |
| **Recall** | 92.83% |
| **F1-Score** | 95.35% |
| **ROC-AUC** | 98.10% |
| **Training Samples** | 386,996 |
| **Test Samples** | 96,749 |
| **Features** | 41 |

---

## 🎓 Technical Stack

- **Language:** Python 3.x
- **ML Framework:** scikit-learn
- **Data Processing:** pandas, numpy
- **Model Serialization:** joblib
- **Optional:** XGBoost for gradient boosting
- **Visualization:** matplotlib (in notebook)
- **Testing:** subprocess for integration testing

---

## 📝 Notes

- **No Hardcoded Whitelist:** System uses heuristic-based reputation scoring
- **Privacy-Friendly:** Only analyzes URL structure, no content fetching
- **Fast Prediction:** Feature extraction is O(n) where n is URL length
- **Scalable:** Can process thousands of URLs per second
- **Interpretable:** Feature importance available for debugging

---

**Last Updated:** Based on current codebase analysis
**Project Status:** Production-ready ML model with CLI interface

