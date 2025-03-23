# Phishing Website Detector Chrome Extension

This Chrome extension uses a machine learning model to detect phishing websites in real-time. It analyzes URLs and provides warnings when potential phishing sites are detected.

## Features

- Real-time URL analysis
- Phishing detection using XGBoost classifier
- Confidence score display
- Visual warnings for suspicious websites
- Browser notifications for phishing sites

## Installation

1. Clone this repository
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the Flask server:
   ```bash
   python app.py
   ```
4. Load the extension in Chrome:
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the extension directory

## Usage

1. The extension will automatically analyze websites as you browse
2. Click the extension icon to see detailed analysis of the current website
3. Warning banners will appear on suspicious websites
4. Browser notifications will be shown for phishing sites

## Technical Details

- The extension uses a Flask API to process URLs
- Features are extracted from URLs using the same method as the training data
- The ML model is an XGBoost classifier trained on URL features
- Real-time analysis is performed using background and content scripts

## Security Note

This extension is for educational purposes only. While it can help identify potential phishing sites, it should not be relied upon as the sole means of protection against phishing attacks.

## License

MIT License 