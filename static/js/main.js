// URL Validation Function
function isValidURL(url) {
    if (!url || !url.trim()) {
        return { valid: false, error: 'URL is required' };
    }

    url = url.trim();

    // Basic checks
    if (url.includes(' ')) {
        return { valid: false, error: 'URL cannot contain spaces' };
    }

    // Check for basic URL patterns
    const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/i;
    const ipPattern = /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?$/;
    const localhostPattern = /^(https?:\/\/)?localhost(:\d+)?$/i;

    // Try to validate
    try {
        // If it starts with http:// or https://, validate as full URL
        if (url.startsWith('http://') || url.startsWith('https://')) {
            try {
                new URL(url);
                return { valid: true, url: url };
            } catch (e) {
                return { valid: false, error: 'Invalid URL format. Please check the URL.' };
            }
        }

        // Check if it's a valid domain, IP, or localhost
        if (urlPattern.test(url) || ipPattern.test(url) || localhostPattern.test(url)) {
            // Add https:// if no protocol
            const fullUrl = url.startsWith('http') ? url : 'https://' + url;
            try {
                new URL(fullUrl);
                return { valid: true, url: fullUrl };
            } catch (e) {
                return { valid: false, error: 'Invalid URL format. Please check the URL.' };
            }
        }

        return { valid: false, error: 'Invalid URL format. Please enter a valid URL (e.g., example.com or https://example.com)' };
    } catch (e) {
        return { valid: false, error: 'Invalid URL format. Please check the URL.' };
    }
}

// DOM Elements
const urlInput = document.getElementById('url-input');
const checkBtn = document.getElementById('check-btn');
const urlError = document.getElementById('url-error');
const resultSection = document.getElementById('result-section');
const resultCard = document.getElementById('result-card');
const resultTitle = document.getElementById('result-title');
const resultIcon = document.getElementById('result-icon');
const resultUrl = document.getElementById('result-url');
const confidenceValue = document.getElementById('confidence-value');
const confidenceFill = document.getElementById('confidence-fill');
const probLegitimate = document.getElementById('prob-legitimate');
const probPhishing = document.getElementById('prob-phishing');
const reputationLevel = document.getElementById('reputation-level');
const reputationScore = document.getElementById('reputation-score');
const modelType = document.getElementById('model-type');
const modelAccuracy = document.getElementById('model-accuracy');

// Real-time URL validation
urlInput.addEventListener('input', function() {
    const url = urlInput.value.trim();
    if (url.length > 0) {
        const validation = isValidURL(url);
        if (!validation.valid) {
            showError(validation.error);
        } else {
            hideError();
        }
    } else {
        hideError();
    }
});

// Enter key handler
urlInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        checkURL();
    }
});

// Check button click handler
checkBtn.addEventListener('click', checkURL);

// Show error message
function showError(message) {
    urlError.textContent = message;
    urlError.style.display = 'block';
    urlInput.classList.add('error');
}

// Hide error message
function hideError() {
    urlError.style.display = 'none';
    urlInput.classList.remove('error');
}

// Check URL function
async function checkURL() {
    const url = urlInput.value.trim();

    // Validate URL before sending
    const validation = isValidURL(url);
    if (!validation.valid) {
        showError(validation.error);
        return;
    }

    hideError();
    
    // Show loading state
    checkBtn.disabled = true;
    checkBtn.querySelector('.btn-text').style.display = 'none';
    checkBtn.querySelector('.btn-loader').style.display = 'inline';
    resultSection.style.display = 'none';

    try {
        const response = await fetch('/api/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: validation.url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Prediction failed');
        }

        if (!data.success) {
            throw new Error(data.error || 'Prediction failed');
        }

        // Display results
        displayResults(data);

    } catch (error) {
        showError(error.message || 'An error occurred. Please try again.');
        resultSection.style.display = 'none';
    } finally {
        // Reset button state
        checkBtn.disabled = false;
        checkBtn.querySelector('.btn-text').style.display = 'inline';
        checkBtn.querySelector('.btn-loader').style.display = 'none';
    }
}

// Display prediction results
function displayResults(data) {
    resultUrl.textContent = data.url;
    
    const isPhishing = data.is_phishing;
    const confidence = data.confidence;
    
    // Set result title and icon
    if (isPhishing) {
        resultTitle.textContent = '⚠️ PHISHING DETECTED';
        resultIcon.textContent = '🚨';
        resultCard.className = 'result-card phishing';
    } else {
        resultTitle.textContent = '✅ LEGITIMATE URL';
        resultIcon.textContent = '✓';
        resultCard.className = 'result-card legitimate';
    }

    // Set confidence
    confidenceValue.textContent = `${confidence.toFixed(1)}%`;
    confidenceFill.style.width = `${confidence}%`;
    confidenceFill.className = `progress-fill ${isPhishing ? 'phishing' : 'legitimate'}`;

    // Set probabilities
    probLegitimate.textContent = `${data.probabilities.legitimate.toFixed(1)}%`;
    probPhishing.textContent = `${data.probabilities.phishing.toFixed(1)}%`;

    // Set reputation
    reputationLevel.textContent = data.reputation_level;
    reputationScore.textContent = (data.reputation_score * 100).toFixed(1) + '%';

    // Show result section
    resultSection.style.display = 'block';
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Load model information
async function loadModelInfo() {
    try {
        const response = await fetch('/api/model-info');
        const data = await response.json();

        if (data.success) {
            modelType.textContent = data.model_type || 'N/A';
            modelAccuracy.textContent = `${data.accuracy.toFixed(2)}%`;
        } else {
            modelType.textContent = 'Error loading model info';
            modelAccuracy.textContent = 'N/A';
        }
    } catch (error) {
        console.error('Error loading model info:', error);
        modelType.textContent = 'Error loading model info';
        modelAccuracy.textContent = 'N/A';
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadModelInfo();
    urlInput.focus();
});

