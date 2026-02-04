# Phishing URL Detection System

A high-accuracy machine learning model trained to detect phishing and spam URLs by combining two comprehensive datasets.

## Model Performance

- **Best Model**: Gradient Boosting Classifier (selected from multiple algorithms)
- **Accuracy**: 94.97% (improved from 87.23%)
- **ROC-AUC Score**: 97.73%
- **Precision**: 97.20%
- **Recall**: 91.60%
- **F1-Score**: 94.32%
- **Training Samples**: 386,996
- **Test Samples**: 96,749
- **Total Features**: 41 URL-based features

### Classification Performance

| Class      | Precision | Recall | F1-Score |
| ---------- | --------- | ------ | -------- |
| Legitimate | 0.93      | 0.98   | 0.95     |
| Phishing   | 0.97      | 0.92   | 0.94     |

## Datasets Used

1. **Mendeley Dataset** (247,950 samples)
   - Source: https://data.mendeley.com/datasets/6tm2d6sz7p/1
   - Features: 41 URL-based features (length, special characters, entropy, domain features, etc.)

2. **UCI PhiUSIIL Phishing URL Dataset** (235,795 samples)
   - Source: https://archive.ics.uci.edu/dataset/327/phishing+websites
   - Features: URL characteristics mapped to Mendeley feature set

**Combined Dataset**: 483,745 total samples with 41 URL-based features

## Installation

1. Install required packages:

```bash
pip install -r requirements.txt
```

## Usage

### Training the Model

You can train the model using either:

#### Option 1: Jupyter Notebook (Recommended for Interactive Training)

The Jupyter notebook provides an interactive environment with better visualization and progress tracking:

```bash
# Install Jupyter if not already installed
pip install jupyter matplotlib

# Launch Jupyter Notebook
jupyter notebook train_model.ipynb
```

Then run all cells sequentially. The notebook includes:

- Step-by-step training process
- Model comparison tables
- Feature importance visualization
- Interactive progress tracking

#### Option 2: Python Script

To train the model using the Python script:

```bash
python train_model.py
```

This will:

- Load and combine both datasets
- Standardize label conventions
- Train multiple models (Random Forest, Gradient Boosting, AdaBoost, XGBoost)
- Select the best performing model based on accuracy and F1-score
- Save the model as `models/phishing_detection_model.pkl` (or set `MODEL_DIR` env var to a custom path)

### Making Predictions

To predict if a URL is phishing:

```bash
python predict_phishing.py <URL>
```

Examples:

```bash
python predict_phishing.py https://www.example.com
python predict_phishing.py google.com
python predict_phishing.py 192.168.1.1
```

## Model Files

- `models/phishing_detection_model.pkl` - Trained model (best performing algorithm). Location configurable via `MODEL_DIR` env var.
- `models/model_features.pkl` - List of feature names used by the model. Location configurable via `MODEL_DIR` env var.
- `model_info.json` - Model metadata and performance metrics (also saved to `models/model_info.json` when training).

## Top Features

The most important features for detection (by importance):

1. URL Length
2. Number of Digits in URL
3. Domain Length
4. Average Subdomain Length
5. Number of Subdomains
6. Number of Special Characters in URL
7. Entropy of Domain
8. Number of Slashes in URL
9. Entropy of URL
10. Path Length

## Supported Input Types

The model can analyze:

- **Full URLs**: `https://www.example.com/path?query=test`
- **Domains**: `example.com` or `www.example.com`
- **IP Addresses**: `192.168.1.1` or `http://8.8.8.8`

**Note**: IP addresses are often flagged as suspicious because they're commonly used in phishing attacks. This is expected behavior for security purposes.

## Model Comparison

The training script tests multiple algorithms:

| Model             | Accuracy       | ROC-AUC | F1-Score |
| ----------------- | -------------- | ------- | -------- |
| Gradient Boosting | 94.97%         | 97.73%  | 94.32%   |
| Random Forest     | 91.70%         | 97.04%  | 90.29%   |
| AdaBoost          | 74.25%         | 80.19%  | 63.96%   |
| XGBoost           | (if available) |         |          |

The best model is automatically selected and saved.

## Notes

- The model uses only URL-based features (no HTML content required)
- Both datasets are combined for maximum training data
- Features are extracted from URL structure, domain characteristics, and entropy
- For production use, consider adding a whitelist for known legitimate IPs if needed

## License

This project uses publicly available datasets for research purposes.
