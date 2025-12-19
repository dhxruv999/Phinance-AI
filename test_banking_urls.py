"""
Test the phishing detection model on unseen dataset (contains both legitimate and phishing URLs)
Tests each URL one by one and displays results
"""

import pandas as pd
import subprocess
import sys
import time

def test_url(url):
    """Test a single URL and return prediction result"""
    try:
        result = subprocess.run(
            ["python3", "predict_phishing.py", url],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Parse output to get prediction
        output = result.stdout
        is_legitimate = "LEGITIMATE" in output and "✓" in output
        is_phishing = "PHISHING" in output and "⚠️" in output
        
        # Extract confidence
        confidence = None
        for line in output.split('\n'):
            if 'Confidence:' in line:
                try:
                    confidence_str = line.split('Confidence:')[1].strip()
                    confidence = float(confidence_str.replace('%', ''))
                except:
                    pass
                break
        
        return {
            'url': url,
            'predicted_legitimate': is_legitimate,
            'predicted_phishing': is_phishing,
            'confidence': confidence,
            'output': output
        }
    except Exception as e:
        return {
            'url': url,
            'predicted_legitimate': False,
            'predicted_phishing': False,
            'confidence': None,
            'correct': False,
            'error': str(e),
            'output': ''
        }

def main():
    csv_file = "Unseen DataSets for testing/Unseen-phishing-dataset.csv"
    
    print("=" * 70)
    print("Testing Phishing Detection Model on Unseen Dataset")
    print("=" * 70)
    
    # Load CSV
    print(f"\nLoading URLs from: {csv_file}")
    try:
        df = pd.read_csv(csv_file)
        print(f"Loaded {len(df)} URLs\n")
    except Exception as e:
        print(f"Error loading CSV: {e}")
        sys.exit(1)
    
    # Test each URL one by one
    results = []
    correct_count = 0
    false_positive_count = 0  # Legitimate flagged as phishing
    false_negative_count = 0  # Phishing flagged as legitimate
    true_positive_count = 0  # Phishing correctly identified
    true_negative_count = 0  # Legitimate correctly identified
    
    for idx, row in df.iterrows():
        url = row['url']
        actual_label = row['label']  # 0 = legitimate, 1 = phishing
        url_num = idx + 1
        
        print(f"\n{'='*70}")
        print(f"Testing URL {url_num}/{len(df)}: {url}")
        print(f"Actual Label: {'PHISHING' if actual_label == 1 else 'LEGITIMATE'}")
        print('='*70)
        
        result = test_url(url)
        result['actual_label'] = actual_label
        result['actual_is_phishing'] = (actual_label == 1)
        result['actual_is_legitimate'] = (actual_label == 0)
        
        # Determine if prediction is correct
        if actual_label == 0:  # Should be legitimate
            result['correct'] = result['predicted_legitimate']
            if result['predicted_legitimate']:
                true_negative_count += 1
                correct_count += 1
            else:
                false_positive_count += 1
        else:  # Should be phishing
            result['correct'] = result['predicted_phishing']
            if result['predicted_phishing']:
                true_positive_count += 1
                correct_count += 1
            else:
                false_negative_count += 1
        
        results.append(result)
        
        # Display result
        if result['correct']:
            status = "✓ CORRECT"
            emoji = "✓"
        else:
            if actual_label == 0:
                status = "✗ FALSE POSITIVE (Legitimate flagged as Phishing)"
            else:
                status = "✗ FALSE NEGATIVE (Phishing flagged as Legitimate)"
            emoji = "⚠️"
        
        confidence_str = f" ({result['confidence']:.2f}% confidence)" if result['confidence'] else ""
        print(f"\nResult: {emoji} {status}{confidence_str}")
        
        if result.get('error'):
            print(f"Error: {result['error']}")
        
        # Show summary so far
        accuracy = (correct_count / url_num) * 100
        print(f"\nProgress: {url_num}/{len(df)} | Correct: {correct_count} | Accuracy: {accuracy:.2f}%")
        print(f"  True Positives: {true_positive_count} | True Negatives: {true_negative_count}")
        print(f"  False Positives: {false_positive_count} | False Negatives: {false_negative_count}")
        
        # Small delay to make output readable
        time.sleep(0.5)
    
    # Final summary
    print("\n" + "=" * 70)
    print("FINAL TEST RESULTS SUMMARY")
    print("=" * 70)
    
    total = len(df)
    accuracy = (correct_count / total * 100) if total > 0 else 0
    
    # Calculate precision, recall, F1
    total_predicted_phishing = true_positive_count + false_positive_count
    total_actual_phishing = true_positive_count + false_negative_count
    total_actual_legitimate = true_negative_count + false_positive_count
    
    precision = (true_positive_count / total_predicted_phishing * 100) if total_predicted_phishing > 0 else 0
    recall = (true_positive_count / total_actual_phishing * 100) if total_actual_phishing > 0 else 0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
    
    print(f"\nTotal URLs tested: {total}")
    print(f"\nConfusion Matrix:")
    print(f"  True Positives (Phishing correctly identified): {true_positive_count}")
    print(f"  True Negatives (Legitimate correctly identified): {true_negative_count}")
    print(f"  False Positives (Legitimate flagged as Phishing): {false_positive_count}")
    print(f"  False Negatives (Phishing flagged as Legitimate): {false_negative_count}")
    
    print(f"\nPerformance Metrics:")
    print(f"  Accuracy: {accuracy:.2f}%")
    print(f"  Precision: {precision:.2f}%")
    print(f"  Recall: {recall:.2f}%")
    print(f"  F1-Score: {f1_score:.2f}%")
    
    # Show confidence statistics
    valid_confidences = [r['confidence'] for r in results if r['confidence'] is not None]
    if valid_confidences:
        print(f"\nConfidence Statistics:")
        print(f"  Average: {sum(valid_confidences)/len(valid_confidences):.2f}%")
        print(f"  Median: {sorted(valid_confidences)[len(valid_confidences)//2]:.2f}%")
        print(f"  Min: {min(valid_confidences):.2f}%")
        print(f"  Max: {max(valid_confidences):.2f}%")
    
    # Show false positives and false negatives
    if false_positive_count > 0:
        print(f"\n⚠️  FALSE POSITIVES ({false_positive_count} legitimate URLs incorrectly flagged as phishing):")
        print("-" * 70)
        for result in results:
            if not result['correct'] and result['actual_is_legitimate']:
                conf = f" ({result['confidence']:.1f}% confidence)" if result['confidence'] else ""
                print(f"  {result['url']}{conf}")
    
    if false_negative_count > 0:
        print(f"\n⚠️  FALSE NEGATIVES ({false_negative_count} phishing URLs incorrectly flagged as legitimate):")
        print("-" * 70)
        for result in results:
            if not result['correct'] and result['actual_is_phishing']:
                conf = f" ({result['confidence']:.1f}% confidence)" if result['confidence'] else ""
                print(f"  {result['url']}{conf}")
    
    # Save detailed results
    output_file = "unseen_dataset_test_results.csv"
    results_df = pd.DataFrame([{
        'url': r['url'],
        'actual_label': r['actual_label'],
        'actual_class': 'PHISHING' if r['actual_is_phishing'] else 'LEGITIMATE',
        'predicted_legitimate': r['predicted_legitimate'],
        'predicted_phishing': r['predicted_phishing'],
        'predicted_class': 'LEGITIMATE' if r['predicted_legitimate'] else 'PHISHING',
        'confidence': r['confidence'],
        'correct': r['correct']
    } for r in results])
    results_df.to_csv(output_file, index=False)
    print(f"\n✓ Detailed results saved to: {output_file}")
    
    print("\n" + "=" * 70)
    
    return correct_count, false_positive_count

if __name__ == "__main__":
    main()
