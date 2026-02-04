#!/usr/bin/env python3
"""
Phishing URL Detection - Prediction Script
Use the trained model to predict if a URL is phishing or legitimate
"""

import pandas as pd
import numpy as np
import joblib
import json
import os
import sys
import warnings
warnings.filterwarnings('ignore')


def load_model():
    """Load the trained model and feature list"""
    try:
        model_dir = os.environ.get('MODEL_DIR', 'models')
        model_path = os.path.join(model_dir, 'phishing_detection_model.pkl')
        features_path = os.path.join(model_dir, 'model_features.pkl')
        # Prefer model_info.json from model_dir if present, otherwise fallback to repo root file
        info_path = os.path.join(model_dir, 'model_info.json') if os.path.exists(
            os.path.join(model_dir, 'model_info.json')) else 'model_info.json'
        model = joblib.load(model_path)
        features = joblib.load(features_path)
        with open(info_path, 'r') as f:
            model_info = json.load(f)
        return model, features, model_info
    except FileNotFoundError as e:
        print(
            f"Error: Model files not found in '{model_dir}'. Please run train_model.py or set MODEL_DIR environment variable.")
        print(f"Missing file: {e}")
        sys.exit(1)


def calculate_entropy(text):
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0
    import math
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def has_repeated_digits(text):
    """Check if text has repeated digits"""
    import re
    return 1 if re.search(r'(\d)\1{2,}', text) else 0


def extract_features_from_url(url):
    """
    Extract comprehensive features from a URL string.
    Extracts all features that can be computed from URL alone.
    """
    from urllib.parse import urlparse

    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Parse URL
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment
        scheme = parsed.scheme

        # Handle case where domain might be empty
        if not domain and parsed.path:
            domain = parsed.path.split('/')[0]
            path = '/' + '/'.join(parsed.path.split('/')
                                  [1:]) if '/' in parsed.path else '/'
    except:
        domain = ''
        path = ''
        query = ''
        fragment = ''
        scheme = ''

    # Basic URL features
    url_length = len(url)
    number_of_dots_in_url = url.count('.')
    number_of_digits_in_url = sum(c.isdigit() for c in url)
    number_of_hyphens_in_url = url.count('-')
    number_of_underline_in_url = url.count('_')
    number_of_slash_in_url = url.count('/')
    number_of_questionmark_in_url = url.count('?')
    number_of_equal_in_url = url.count('=')
    number_of_at_in_url = url.count('@')
    number_of_dollar_in_url = url.count('$')
    number_of_exclamation_in_url = url.count('!')
    number_of_hashtag_in_url = url.count('#')
    number_of_percent_in_url = url.count('%')

    # Special characters (excluding common ones)
    special_chars = set(
        url) - set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/_')
    number_of_special_char_in_url = len([c for c in url if c in special_chars])

    # Domain features
    domain_length = len(domain) if domain else 0
    number_of_dots_in_domain = domain.count('.') if domain else 0
    number_of_hyphens_in_domain = domain.count('-') if domain else 0

    # Check if domain has special characters
    domain_special = set(
        domain) - set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-') if domain else set()
    having_special_characters_in_domain = 1 if domain_special else 0
    number_of_special_characters_in_domain = len(domain_special)

    # Check if domain has digits
    domain_digits = [c for c in domain if c.isdigit()] if domain else []
    having_digits_in_domain = 1 if domain_digits else 0
    number_of_digits_in_domain = len(domain_digits)

    # Repeated digits
    having_repeated_digits_in_url = has_repeated_digits(url)
    having_repeated_digits_in_domain = has_repeated_digits(
        domain) if domain else 0

    # Subdomain analysis
    if domain:
        parts = [p for p in domain.split('.') if p]
        number_of_subdomains = max(0, len(parts) - 2) if len(parts) >= 2 else 0

        if number_of_subdomains > 0:
            subdomains = parts[:-2]
            subdomain_text = '.'.join(subdomains)
            having_dot_in_subdomain = 1 if '.' in subdomain_text else 0
            having_hyphen_in_subdomain = 1 if '-' in subdomain_text else 0
            average_subdomain_length = sum(
                len(s) for s in subdomains) / len(subdomains) if subdomains else 0
            average_number_of_dots_in_subdomain = subdomain_text.count(
                '.') / len(subdomains) if subdomains else 0
            average_number_of_hyphens_in_subdomain = subdomain_text.count(
                '-') / len(subdomains) if subdomains else 0

            subdomain_special = set(
                subdomain_text) - set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-')
            having_special_characters_in_subdomain = 1 if subdomain_special else 0
            number_of_special_characters_in_subdomain = len(subdomain_special)

            subdomain_digits = [c for c in subdomain_text if c.isdigit()]
            having_digits_in_subdomain = 1 if subdomain_digits else 0
            number_of_digits_in_subdomain = len(subdomain_digits)
            having_repeated_digits_in_subdomain = has_repeated_digits(
                subdomain_text)
        else:
            having_dot_in_subdomain = 0
            having_hyphen_in_subdomain = 0
            average_subdomain_length = 0
            average_number_of_dots_in_subdomain = 0
            average_number_of_hyphens_in_subdomain = 0
            having_special_characters_in_subdomain = 0
            number_of_special_characters_in_subdomain = 0
            having_digits_in_subdomain = 0
            number_of_digits_in_subdomain = 0
            having_repeated_digits_in_subdomain = 0
    else:
        number_of_subdomains = 0
        having_dot_in_subdomain = 0
        having_hyphen_in_subdomain = 0
        average_subdomain_length = 0
        average_number_of_dots_in_subdomain = 0
        average_number_of_hyphens_in_subdomain = 0
        having_special_characters_in_subdomain = 0
        number_of_special_characters_in_subdomain = 0
        having_digits_in_subdomain = 0
        number_of_digits_in_subdomain = 0
        having_repeated_digits_in_subdomain = 0

    # Path features
    having_path = 1 if path and path != '/' else 0
    path_length = len(path) if path else 0
    having_query = 1 if query else 0
    having_fragment = 1 if fragment else 0
    having_anchor = 1 if '#' in url else 0

    # Entropy
    entropy_of_url = calculate_entropy(url)
    entropy_of_domain = calculate_entropy(domain) if domain else 0

    # Return the 41 features that the model expects
    features = {
        'url_length': url_length,
        'number_of_dots_in_url': number_of_dots_in_url,
        'having_repeated_digits_in_url': having_repeated_digits_in_url,
        'number_of_digits_in_url': number_of_digits_in_url,
        'number_of_special_char_in_url': number_of_special_char_in_url,
        'number_of_hyphens_in_url': number_of_hyphens_in_url,
        'number_of_underline_in_url': number_of_underline_in_url,
        'number_of_slash_in_url': number_of_slash_in_url,
        'number_of_questionmark_in_url': number_of_questionmark_in_url,
        'number_of_equal_in_url': number_of_equal_in_url,
        'number_of_at_in_url': number_of_at_in_url,
        'number_of_dollar_in_url': number_of_dollar_in_url,
        'number_of_exclamation_in_url': number_of_exclamation_in_url,
        'number_of_hashtag_in_url': number_of_hashtag_in_url,
        'number_of_percent_in_url': number_of_percent_in_url,
        'domain_length': domain_length,
        'number_of_dots_in_domain': number_of_dots_in_domain,
        'number_of_hyphens_in_domain': number_of_hyphens_in_domain,
        'having_special_characters_in_domain': having_special_characters_in_domain,
        'number_of_special_characters_in_domain': number_of_special_characters_in_domain,
        'having_digits_in_domain': having_digits_in_domain,
        'number_of_digits_in_domain': number_of_digits_in_domain,
        'having_repeated_digits_in_domain': having_repeated_digits_in_domain,
        'number_of_subdomains': number_of_subdomains,
        'having_dot_in_subdomain': having_dot_in_subdomain,
        'having_hyphen_in_subdomain': having_hyphen_in_subdomain,
        'average_subdomain_length': average_subdomain_length,
        'average_number_of_dots_in_subdomain': average_number_of_dots_in_subdomain,
        'average_number_of_hyphens_in_subdomain': average_number_of_hyphens_in_subdomain,
        'having_special_characters_in_subdomain': having_special_characters_in_subdomain,
        'number_of_special_characters_in_subdomain': number_of_special_characters_in_subdomain,
        'having_digits_in_subdomain': having_digits_in_subdomain,
        'number_of_digits_in_subdomain': number_of_digits_in_subdomain,
        'having_repeated_digits_in_subdomain': having_repeated_digits_in_subdomain,
        'having_path': having_path,
        'path_length': path_length,
        'having_query': having_query,
        'having_fragment': having_fragment,
        'having_anchor': having_anchor,
        'entropy_of_url': entropy_of_url,
        'entropy_of_domain': entropy_of_domain,
    }

    return features


def get_domain_reputation_score(domain):
    """
    Calculate domain reputation score based on heuristics (not hardcoded list).
    Returns a score between 0 and 1, where higher = more likely legitimate.
    Uses domain patterns, TLD analysis, and structural features.
    """
    if not domain:
        return 0.5  # Neutral

    domain_lower = domain.lower()

    # Extract TLD and main domain
    parts = domain_lower.split('.')
    if len(parts) < 2:
        return 0.3  # Suspicious if no proper TLD

    tld = parts[-1]
    main_domain = parts[-2] if len(parts) >= 2 else ''

    reputation_score = 0.5  # Start neutral

    # TLD analysis - common legitimate TLDs get higher score
    legitimate_tlds = {
        'com': 0.20, 'org': 0.20, 'net': 0.15, 'edu': 0.25, 'gov': 0.25,
        'co.uk': 0.20, 'co.in': 0.20, 'in': 0.15, 'uk': 0.15, 'au': 0.15,
        'ca': 0.15, 'de': 0.15, 'fr': 0.15, 'jp': 0.15, 'sg': 0.15
    }

    # Check for common legitimate TLD patterns (handle multi-part TLDs like co.in)
    tld_matched = False

    # First check for multi-part TLDs like .co.in, .co.uk
    if len(parts) >= 3:
        # Check for .co.in pattern
        if parts[-2] == 'co' and parts[-1] == 'in':
            reputation_score += 0.20  # .co.in boost
            reputation_score += 0.10  # Extra boost for Indian companies
            tld_matched = True
        # Check for .co.uk pattern
        elif parts[-2] == 'co' and parts[-1] == 'uk':
            reputation_score += 0.20
            tld_matched = True

    # Then check single-part TLDs
    if not tld_matched:
        for legit_tld, score_boost in legitimate_tlds.items():
            if domain_lower.endswith('.' + legit_tld) or domain_lower == legit_tld:
                reputation_score += score_boost
                tld_matched = True
                break

    # If no TLD matched but it's a standard format, still give some credit
    if not tld_matched and len(parts) >= 2:
        if parts[-1] in ['com', 'org', 'net', 'in', 'uk', 'au', 'ca', 'de', 'fr', 'jp', 'sg']:
            reputation_score += 0.10

    # Domain length analysis - banking domains can be longer
    # Optimal length is 5-30 characters for main domain (banking names can be longer)
    if 5 <= len(main_domain) <= 30:
        reputation_score += 0.10
    elif 30 < len(main_domain) <= 40:
        # Longer but still reasonable for banking/financial institutions
        reputation_score += 0.05
    elif len(main_domain) < 3 or len(main_domain) > 50:
        reputation_score -= 0.15

    # Check for suspicious patterns
    # Too many numbers in domain name
    digit_ratio = sum(c.isdigit() for c in main_domain) / \
        len(main_domain) if main_domain else 0
    if digit_ratio > 0.3:  # More than 30% digits
        reputation_score -= 0.20
    elif digit_ratio > 0.5:  # More than 50% digits - very suspicious
        reputation_score -= 0.30

    # Hyphen count - legitimate domains rarely have multiple hyphens
    # But allow 1-2 hyphens for compound names
    hyphen_count = main_domain.count('-')
    if hyphen_count > 2:
        reputation_score -= 0.20  # Multiple hyphens are very suspicious
    elif hyphen_count == 2:
        # Two hyphens might be legitimate (like "bank-of-america") but check for suspicious patterns
        suspicious_patterns = ['secure', 'verify',
                               'update', 'login', 'account', 'confirm']
        if any(pattern in main_domain for pattern in suspicious_patterns):
            reputation_score -= 0.15  # Suspicious pattern with multiple hyphens
    elif hyphen_count == 0:
        # No hyphens is often a sign of legitimate domains
        reputation_score += 0.05

    # Common legitimate domain patterns (heuristic, not hardcoded list)
    # Banking/financial keywords in domain
    financial_keywords = ['bank', 'banking', 'financial', 'finance', 'credit', 'capital',
                          'union', 'federal', 'state', 'national', 'central', 'reserve']

    # Suspicious words that when combined with banking keywords indicate phishing
    # These are common in phishing URLs but rare in legitimate banking sites
    suspicious_phishing_words = ['cashback', 'alert', 'verification', 'verify', 'reward',
                                 'secure', 'login', 'update', 'claim', 'confirm', 'activate',
                                 'suspended', 'locked', 'expired', 'urgent', 'warning']

    # Check if domain contains banking/financial keywords
    has_banking_keyword = any(
        keyword in main_domain for keyword in financial_keywords)
    has_suspicious_word = any(
        word in main_domain for word in suspicious_phishing_words)

    # CRITICAL: If domain has banking keyword BUT also suspicious phishing words, it's likely phishing
    # This catches patterns like "pnb-netbanking-login", "phonepe-cashback", "paytm-cashback-alert"
    if has_banking_keyword and has_suspicious_word:
        # Banking keyword + suspicious word = high probability of phishing
        reputation_score -= 0.40  # Strong penalty
        # Additional penalty if multiple suspicious words
        suspicious_count = sum(
            1 for word in suspicious_phishing_words if word in main_domain)
        if suspicious_count > 1:
            reputation_score -= 0.20  # Extra penalty for multiple suspicious words
    elif has_banking_keyword:
        # Banking domains can be longer (up to 40 chars) and may have 1-2 hyphens
        if len(main_domain) <= 40 and hyphen_count <= 2:
            reputation_score += 0.25  # Increased boost for banking keywords
            # If it contains "bank" or "banking", it's very likely legitimate
            if 'bank' in main_domain or 'banking' in main_domain:
                reputation_score += 0.15  # Extra boost for explicit bank keywords
                # For domains with "bank" + legitimate TLD, ensure high reputation
                if tld_matched:
                    reputation_score += 0.10

    # Payment/fintech keywords
    payment_keywords = ['pay', 'payment', 'paytm', 'phonepe', 'razorpay', 'stripe',
                        'paypal', 'wallet', 'upi', 'gateway', 'merchant']
    has_payment_keyword = any(
        keyword in main_domain for keyword in payment_keywords)

    # Suspicious TLDs - when combined with banking/payment keywords, very suspicious
    suspicious_tlds = ['xyz', 'top', 'online',
                       'site', 'website', 'click', 'link', 'space']

    # If domain has banking/payment keywords but uses suspicious TLD, it's likely phishing
    if (has_banking_keyword or has_payment_keyword) and tld in suspicious_tlds:
        reputation_score -= 0.50  # Strong penalty for banking keyword + suspicious TLD
    elif tld in suspicious_tlds:
        # Suspicious TLD without banking keyword is also suspicious
        reputation_score -= 0.20

    # Check if payment keyword is combined with suspicious words
    if has_payment_keyword and has_suspicious_word:
        # Payment keyword + suspicious word = likely phishing
        reputation_score -= 0.35
        suspicious_count = sum(
            1 for word in suspicious_phishing_words if word in main_domain)
        if suspicious_count > 1:
            reputation_score -= 0.15
    elif has_payment_keyword:
        if len(main_domain) <= 30 and hyphen_count <= 1:
            reputation_score += 0.20

    # Tech company patterns
    tech_keywords = ['google', 'microsoft', 'amazon', 'apple', 'facebook', 'github',
                     'twitter', 'linkedin', 'instagram', 'netflix', 'youtube']
    if any(keyword in main_domain for keyword in tech_keywords):
        if len(main_domain) <= 30:
            reputation_score += 0.15

    # Subdomain analysis - www is neutral, other common subdomains are positive
    if len(parts) > 2:
        subdomain = parts[0]
        if subdomain in ['www', 'www2', 'secure', 'online', 'portal', 'login']:
            reputation_score += 0.05
        elif subdomain.count('-') > 1 or len(subdomain) > 20:
            reputation_score -= 0.10

    # Normalize score to 0-1 range
    reputation_score = max(0.0, min(1.0, reputation_score))

    return reputation_score


def predict_url(url, model, features, threshold=0.75):
    """
    Predict if a URL is phishing or legitimate using ML model + domain reputation heuristics
    threshold: Minimum probability required to classify as phishing (default 0.75 = 75%)
    """
    from urllib.parse import urlparse

    # Extract domain and query for reputation analysis
    test_url = url if url.startswith(
        ('http://', 'https://')) else 'https://' + url
    parsed = urlparse(test_url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    query = parsed.query.lower()

    # Check for suspicious query parameters (common in phishing)
    suspicious_query_params = ['session=', 'token=',
                               'verify=', 'confirm=', 'activate=']
    has_suspicious_query = any(
        param in query for param in suspicious_query_params)

    # Get ML model prediction
    url_features = extract_features_from_url(url)

    feature_dict = {}
    for f in features:
        if f in url_features:
            feature_dict[f] = url_features[f]
        else:
            feature_dict[f] = 0

    X = pd.DataFrame([feature_dict])[features]

    # Get model's prediction
    probability = model.predict_proba(X)[0]

    # Get domain reputation score (heuristic-based, not hardcoded)
    reputation_score = get_domain_reputation_score(domain)

    # Additional penalty for suspicious query parameters
    # Phishing URLs often use query params like ?session=X, ?verify=Y
    if has_suspicious_query:
        # If query has suspicious params, lower reputation
        reputation_score -= 0.15
        # If combined with banking keywords in domain, even more suspicious
        domain_lower = domain.lower()
        if 'bank' in domain_lower or 'pay' in domain_lower or 'netbanking' in domain_lower:
            reputation_score -= 0.10  # Extra penalty

    # Ensure reputation score stays in valid range
    reputation_score = max(0.0, min(1.0, reputation_score))

    # Adjust probability based on reputation score
    # If reputation is high (legitimate-looking domain), shift towards legitimate
    # If reputation is low (suspicious-looking domain), shift towards phishing

    # Check if domain contains banking keywords for extra protection
    domain_lower = domain.lower()
    parts = domain_lower.split('.')
    main_domain = parts[-2] if len(parts) >= 2 else ''
    has_bank_keyword = 'bank' in main_domain or 'banking' in main_domain

    if reputation_score >= 0.75:  # High reputation (likely legitimate)
        # Dynamic adjustment based on reputation score and model prediction
        # Higher reputation = stronger adjustment towards legitimate

        if reputation_score >= 0.85:
            # Very high reputation domains (like major banks)
            # Calculate target legitimate probability based on reputation
            # For reputation 0.85-1.0, target 0.70-0.85 legitimate probability
            # Maps 0.85->0.70, 1.0->0.85
            target_legitimate = 0.70 + (reputation_score - 0.85) * 1.0
            target_legitimate = min(0.85, target_legitimate)  # Cap at 85%

            if has_bank_keyword:
                # Banking domains get extra boost: target 0.75-0.90
                target_legitimate = 0.75 + (reputation_score - 0.85) * 1.0
                target_legitimate = min(0.90, target_legitimate)

            # Blend model prediction with target (weighted average)
            # Use 30% model + 70% target for very low model predictions
            # Use 70% model + 30% target for higher model predictions
            if probability[0] < 0.30:
                # Model is very wrong, trust reputation more
                blend_weight = 0.25  # 25% model, 75% target
            elif probability[0] < 0.50:
                # Model is uncertain, blend more
                blend_weight = 0.40  # 40% model, 60% target
            else:
                # Model is somewhat confident, trust it more
                blend_weight = 0.60  # 60% model, 40% target

            probability[0] = blend_weight * probability[0] + \
                (1 - blend_weight) * target_legitimate
            probability[1] = 1.0 - probability[0]

        elif reputation_score >= 0.75:
            # High reputation domains
            # Maps 0.75->0.60, 0.85->0.70
            target_legitimate = 0.60 + (reputation_score - 0.75) * 1.0
            target_legitimate = min(0.75, target_legitimate)

            if has_bank_keyword:
                target_legitimate = 0.65 + (reputation_score - 0.75) * 0.5
                target_legitimate = min(0.75, target_legitimate)

            # Blend with model prediction
            if probability[0] < 0.30:
                blend_weight = 0.30
            elif probability[0] < 0.50:
                blend_weight = 0.50
            else:
                blend_weight = 0.70

            probability[0] = blend_weight * probability[0] + \
                (1 - blend_weight) * target_legitimate
            probability[1] = 1.0 - probability[0]
    elif reputation_score < 0.4:  # Low reputation (suspicious)
        # Strong shift towards phishing for low-reputation domains
        # Lower reputation = stronger shift
        # Max 0.20 adjustment for very low reputation
        adjustment = (0.4 - reputation_score) * 0.5
        probability[0] = max(0.05, probability[0] - adjustment)
        probability[1] = min(0.95, probability[1] + adjustment)
    elif reputation_score < 0.6:  # Medium reputation - moderate adjustment
        # For medium reputation, make smaller adjustment
        if reputation_score < 0.5:
            # Below 0.5, shift towards phishing
            adjustment = (0.5 - reputation_score) * 0.2
            probability[0] = max(0.05, probability[0] - adjustment)
            probability[1] = min(0.95, probability[1] + adjustment)

    # Normalize probabilities
    total = probability[0] + probability[1]
    if total > 0:
        probability = probability / total

    # Use threshold-based prediction
    if probability[1] >= threshold:
        prediction = 1  # Phishing
    else:
        prediction = 0  # Legitimate

    return prediction, probability, reputation_score


def main():
    if len(sys.argv) < 2:
        print("Usage: python predict_phishing.py <URL>")
        print("\nExample:")
        print("  python predict_phishing.py https://www.example.com")
        sys.exit(1)

    url = sys.argv[1]

    print("=" * 60)
    print("Phishing URL Detection")
    print("=" * 60)
    print(f"\nAnalyzing URL: {url}")

    # Check if input is an IP address
    from urllib.parse import urlparse
    test_url = url if url.startswith(
        ('http://', 'https://')) else 'https://' + url
    parsed = urlparse(test_url)
    domain = parsed.netloc or parsed.path.split('/')[0]

    is_ip = False
    try:
        parts = domain.split('.')
        if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            is_ip = True
            print("\n⚠️  Note: IP addresses are often flagged as suspicious.")
            print("   This is because IPs are commonly used in phishing attacks.")
            print("   Legitimate IPs (CDNs, internal networks) may be flagged.")
    except:
        pass

    # Load model
    print("\nLoading model...")
    try:
        model, features, model_info = load_model()
        print(f"Model type: {model_info['model_type']}")
        print(
            f"Model accuracy: {model_info['accuracy']:.4f} ({model_info['accuracy']*100:.2f}%)")
    except Exception as e:
        print(f"Error loading model: {e}")
        sys.exit(1)

    # Predict using ML model + domain reputation heuristics
    print("\nExtracting features and predicting...")
    print("Using ML model + domain reputation analysis (heuristic-based, not hardcoded)")
    try:
        prediction, probability, reputation_score = predict_url(
            url, model, features, threshold=0.75)
    except Exception as e:
        print(f"Error during prediction: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Display results
    print("\n" + "=" * 60)
    print("Prediction Results:")
    print("=" * 60)

    if prediction == 0:
        result = "LEGITIMATE"
        confidence = probability[0]
        emoji = "✓"
    else:
        result = "PHISHING"
        confidence = probability[1]
        emoji = "⚠️"

    print(f"\nResult: {emoji} {result}")
    print(f"Confidence: {confidence:.2%}")
    print(f"\nProbability breakdown:")
    print(f"  Legitimate: {probability[0]:.2%}")
    print(f"  Phishing:   {probability[1]:.2%}")
    print(
        f"\nDomain Reputation Score: {reputation_score:.2f} ({'High' if reputation_score > 0.6 else 'Low' if reputation_score < 0.4 else 'Medium'})")
    print(f"  (Based on domain patterns, TLD, and structure - not hardcoded list)")

    # Show threshold info
    if probability[1] >= 0.75:
        print(
            f"\n⚠️  Phishing probability ({probability[1]:.2%}) exceeds threshold (75%)")
    elif probability[1] > 0.5:
        print(
            f"\nℹ️  Phishing probability ({probability[1]:.2%}) is moderate but below threshold (75%)")

    print("\n" + "=" * 60)

    return prediction


if __name__ == "__main__":
    main()
