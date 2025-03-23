from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
import pickle
import re
from urllib.parse import urlparse
import tldextract
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app)

# Load the model
try:
    with open('phishing_model_new.pkl', 'rb') as f:
        model = pickle.load(f)
    print("\n=== Model Loading ===")
    print("Model loaded successfully")
    print("Model type:", type(model).__name__)
except Exception as e:
    print(f"\nError loading model: {str(e)}")
    raise

def extract_features(url):
    features = {}
    
    # Parse URL
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    # Basic URL features
    features['Have_IP'] = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url) else 0
    features['Have_At'] = 1 if '@' in url else 0
    features['URL_Length'] = len(url)
    features['URL_Depth'] = len([x for x in path.split('/') if x])
    features['Redirection'] = 1 if '//' in url[7:] else 0
    features['https_Domain'] = 1 if url.startswith('https') else 0
    
    # Domain features
    shortening_services = ['bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co', 'tinyurl', 'tr.im']
    features['TinyURL'] = 1 if any(service in url.lower() for service in shortening_services) else 0
    features['Prefix/Suffix'] = 1 if '-' in domain else 0
    
    # Additional URL features
    features['Sub_Domain'] = len(domain.split('.')) - 1
    features['Multi_Domain'] = 1 if features['Sub_Domain'] > 1 else 0
    features['SSL_State'] = 1 if url.startswith('https') else 0
    features['Domain_Length'] = len(domain)
    features['Favicon'] = 0  # Default value
    
    try:
        # DNS and Domain features
        features['DNS_Record'] = 1
        features['Web_Traffic'] = 1
        features['Domain_Age'] = 1
        features['Domain_End'] = 1
        
        # Try to get domain age
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                domain_age = (datetime.now() - creation_date).days
                features['Domain_Age'] = 1 if domain_age > 180 else 0
        except:
            features['Domain_Age'] = 0
        
        # HTML and JavaScript features
        try:
            response = requests.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for iframes
            features['iFrame'] = 1 if soup.find_all('iframe') else 0
            
            # Check for status bar customization
            scripts = soup.find_all('script')
            features['Status_Bar_Cust'] = 1 if any('window.status' in str(script) for script in scripts) else 0
            
            # Check for right click disabled
            features['Right_Click'] = 1 if 'oncontextmenu' in response.text.lower() else 0
            
            # Check for popup windows
            features['Popup_Window'] = 1 if 'window.open' in response.text.lower() else 0
            
            # Server form handler
            forms = soup.find_all('form')
            features['Server_Form_Handler'] = 1 if any(not form.get('action', '').startswith('/') for form in forms) else 0
            
            # Information submission to email
            features['Submitting_to_Email'] = 1 if 'mailto:' in response.text.lower() or 'mail()' in response.text.lower() else 0
            
            # Abnormal URL
            features['Abnormal_URL'] = 1 if domain not in url else 0
            
            # Website Forwarding
            features['Web_Forwards'] = len(response.history)
            
            # Mouse Over
            features['Mouse_Over'] = 1 if 'onmouseover' in response.text.lower() else 0
            
        except:
            features.update({
                'iFrame': 0,
                'Status_Bar_Cust': 0,
                'Right_Click': 0,
                'Popup_Window': 0,
                'Server_Form_Handler': 0,
                'Submitting_to_Email': 0,
                'Abnormal_URL': 1,
                'Web_Forwards': 0,
                'Mouse_Over': 0
            })
        
    except Exception as e:
        print(f"Error in feature extraction: {str(e)}")
        features.update({
            'DNS_Record': 0,
            'Web_Traffic': 0,
            'Domain_Age': 0,
            'Domain_End': 0,
            'iFrame': 0,
            'Status_Bar_Cust': 0,
            'Right_Click': 0,
            'Popup_Window': 0,
            'Server_Form_Handler': 0,
            'Submitting_to_Email': 0,
            'Abnormal_URL': 1,
            'Web_Forwards': 0,
            'Mouse_Over': 0
        })
    
    return features

@app.route('/')
def home():
    return jsonify({'message': 'Phishing Website Detector API is running'})

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        # Extract features
        features = extract_features(url)
        print("\n=== Feature Extraction ===")
        print("URL:", url)
        print("Extracted features:", features)
        
        # Convert to DataFrame with specific column order
        feature_order = [
            'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
            'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic',
            'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 'Right_Click',
            'Web_Forwards', 'Sub_Domain', 'Multi_Domain', 'SSL_State', 'Domain_Length',
            'Favicon', 'Status_Bar_Cust', 'Popup_Window', 'Server_Form_Handler',
            'Submitting_to_Email'
        ]
        
        df = pd.DataFrame([features])[feature_order]
        print("\n=== DataFrame Info ===")
        print("DataFrame shape:", df.shape)
        print("DataFrame columns:", df.columns.tolist())
        print("DataFrame values:\n", df.values)
        
        # Make prediction
        prediction = model.predict(df)
        probability = model.predict_proba(df)
        print("\n=== Model Output ===")
        print("Raw prediction:", prediction)
        print("Raw probability:", probability)
        print("Model type:", type(model).__name__)
        
        # Calculate confidence with improved logic
        confidence = float(probability[0][1])
        
        # Adjust confidence thresholds for better accuracy
        if confidence > 0.6:  # Lowered threshold for phishing detection
            is_phishing = True
            confidence = min(0.99, confidence * 1.2)  # Increased boost for high confidence
        elif confidence < 0.3:  # Increased threshold for legitimate sites
            is_phishing = False
            confidence = max(0.01, confidence * 0.8)  # Increased reduction for low confidence
        else:
            is_phishing = confidence > 0.5
        
        print("\n=== Confidence Calculation ===")
        print("Calculated confidence:", confidence)
        print("Prediction class:", prediction[0])
        print("Probability array:", probability[0])
        
        # Add more detailed result
        result = {
            'prediction': 'Phishing' if is_phishing else 'Legitimate',
            'confidence': confidence,
            'features': features,
            'url': url,
            'domain': domain,
            'raw_probability': probability.tolist(),
            'raw_prediction': prediction.tolist(),
            'model_type': type(model).__name__
        }
        
        return jsonify(result)
        
    except Exception as e:
        print(f"\n=== Error in prediction ===\n{str(e)}")
        return jsonify({'error': str(e), 'confidence': 0.0}), 500

if __name__ == '__main__':
    app.run(debug=True) 