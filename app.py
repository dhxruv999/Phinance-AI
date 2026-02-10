"""
Flask Backend API for Phishing URL Detection System
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_compress import Compress
import sys
import traceback

# Import prediction functions from predict_phishing.py
from predict_phishing import load_model, predict_url

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests
Compress(app)  # Enable gzip compression for responses

# Configure caching for static files (CSS, JS, images)
# Cache for 1 year (31536000 seconds)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000

# Load model once at startup
print("Loading ML model...")
try:
    model, features, model_info = load_model()
    print(
        f"✓ Model loaded: {model_info['model_type']} (Accuracy: {model_info['accuracy']*100:.2f}%)")
except Exception as e:
    print(f"✗ Error loading model: {e}")
    model = None
    features = None
    model_info = None


@app.route('/')
def landing():
    """Serve the landing page"""
    return render_template('landing.html')


@app.route('/analyze')
def index():
    """Serve the main analysis page"""
    return render_template('index.html')


def is_valid_url(url):
    """Validate URL format"""
    from urllib.parse import urlparse
    import re

    if not url or not url.strip():
        return False, 'URL is required'

    url = url.strip()

    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlparse(url)

        # Check if has netloc (domain) or path
        if not parsed.netloc and not parsed.path:
            return False, 'Invalid URL format. Please enter a valid URL (e.g., example.com or https://example.com)'

        # Basic validation: should have at least a domain or IP
        domain = parsed.netloc or parsed.path.split('/')[0]

        if not domain:
            return False, 'Invalid URL format. Please enter a valid URL.'

        # Check for invalid characters
        if ' ' in url:
            return False, 'URL cannot contain spaces. Please enter a valid URL.'

        # Check if it's a valid domain or IP pattern
        # Domain pattern (allows subdomains, hyphens, etc.)
        domain_pattern = r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$|^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$'
        # IP pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # Localhost
        localhost_pattern = r'^localhost(:[0-9]+)?$'

        # Remove port if present for validation
        domain_without_port = domain.split(':')[0]

        if not (re.match(domain_pattern, domain_without_port, re.IGNORECASE) or
                re.match(ip_pattern, domain_without_port) or
                re.match(localhost_pattern, domain_without_port, re.IGNORECASE)):
            return False, 'Invalid domain or IP address format. Please enter a valid URL.'

        return True, url

    except Exception as e:
        return False, f'Invalid URL format: {str(e)}'


@app.route('/api/predict', methods=['POST'])
def predict():
    """API endpoint for URL prediction"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({
                'success': False,
                'error': 'URL is required'
            }), 400

        # Validate URL format
        is_valid, validation_result = is_valid_url(url)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': validation_result
            }), 400

        # Use validated/normalized URL
        url = validation_result

        if not model:
            return jsonify({
                'success': False,
                'error': 'Model not loaded. Please check server logs.'
            }), 500

        # Make prediction
        prediction, probability, reputation_score = predict_url(
            url, model, features, threshold=0.75)

        # Determine result
        is_phishing = (prediction == 1)
        confidence = probability[1] if is_phishing else probability[0]

        # Get reputation level
        if reputation_score > 0.6:
            reputation_level = 'High'
        elif reputation_score < 0.4:
            reputation_level = 'Low'
        else:
            reputation_level = 'Medium'

        return jsonify({
            'success': True,
            'url': url,
            'is_phishing': is_phishing,
            'confidence': float(confidence) * 100,
            'probabilities': {
                'legitimate': float(probability[0]) * 100,
                'phishing': float(probability[1]) * 100
            },
            'reputation_score': float(reputation_score),
            'reputation_level': reputation_level,
            'model_info': {
                'type': model_info['model_type'],
                'accuracy': model_info['accuracy'] * 100
            }
        })

    except Exception as e:
        print(f"Error in prediction: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/model-info', methods=['GET'])
def model_info_endpoint():
    """Get model information"""
    if not model_info:
        return jsonify({
            'success': False,
            'error': 'Model not loaded'
        }), 500

    return jsonify({
        'success': True,
        'model_type': model_info['model_type'],
        'accuracy': model_info['accuracy'] * 100,
        'precision': model_info.get('precision', 0) * 100,
        'recall': model_info.get('recall', 0) * 100,
        'f1_score': model_info.get('f1_score', 0) * 100,
        'roc_auc': model_info.get('roc_auc', 0) * 100,
        'n_features': model_info.get('n_features', 0),
        'n_train_samples': model_info.get('n_train_samples', 0),
        'n_test_samples': model_info.get('n_test_samples', 0)
    })


@app.route('/api/health', methods=['GET'])
def health():
    if model is None:
        return jsonify({
            'status': 'unhealthy',
            'model_loaded': False,
            'reason': 'Model not loaded'
        }), 500

    return jsonify({
        'status': 'healthy',
        'model_loaded': True
    }), 200


if __name__ == '__main__':
    if model is None:
        print("⚠️  Warning: Model not loaded. Please ensure model files exist.")
        print("   Run: MODEL_DIR=models python train_model.py (or set MODEL_DIR to your models path)")

    print("\n" + "="*60)
    print("Phishing Detection API Server")
    print("="*60)
    print("\nStarting server on http://localhost:5001")
    print("Press Ctrl+C to stop\n")

    app.run(debug=False, host='0.0.0.0', port=5001)
