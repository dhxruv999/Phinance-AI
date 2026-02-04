#!/bin/bash

# Phishing Detection System - Server Startup Script

echo "============================================================"
echo "Phishing URL Detection System - Starting Server"
echo "============================================================"
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed"
    exit 1
fi

# Check if required packages are installed
echo "Checking dependencies..."
python3 -c "import flask" 2>/dev/null || {
    echo "⚠️  Flask not found. Installing dependencies..."
    pip3 install -r requirements.txt
}

# Check if model files exist (MODEL_DIR defaults to 'models' if not set)
MODEL_DIR="${MODEL_DIR:-models}"

# Warn if model file not found in MODEL_DIR
if [ ! -f "$MODEL_DIR/phishing_detection_model.pkl" ]; then
    echo "⚠️  Warning: Model file not found in $MODEL_DIR!"
    echo "   Please run: MODEL_DIR=$MODEL_DIR python3 train_model.py"
    echo ""
fi

# Kill any existing server on port 5001
lsof -ti:5001 | xargs kill -9 2>/dev/null || true

# Start the server
echo "Starting Flask server on http://localhost:5001"
echo "Press Ctrl+C to stop the server"
echo ""
echo "Opening browser..."
sleep 2
open http://localhost:5001 2>/dev/null || echo "Please open http://localhost:5001 in your browser"

# Run the Flask app
python3 app.py

