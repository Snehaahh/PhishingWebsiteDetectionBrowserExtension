import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle
from urllib.parse import urlparse
import re
import tldextract
import whois
from datetime import datetime
import socket
import requests
from bs4 import BeautifulSoup

def extract_features_for_training(url, label):
    features = {}
    try:
        # Basic URL features
        features['url_length'] = len(url)
        
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        # Domain features
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        
        # Special characters
        features['special_chars'] = len(re.findall(r'[^a-zA-Z0-9]', url))
        features['special_chars_domain'] = len(re.findall(r'[^a-zA-Z0-9\-\.]', domain))
        
        # Digits
        features['digits'] = len(re.findall(r'\d', url))
        features['digits_domain'] = len(re.findall(r'\d', domain))
        
        # Domain specific
        ext = tldextract.extract(url)
        subdomains = ext.subdomain.split('.')
        features['subdomain_count'] = len(subdomains)
        features['domain_tokens'] = len(ext.domain.split('-'))
        
        # Security indicators
        features['https'] = 1 if url.startswith('https') else 0
        features['http_in_path'] = 1 if 'http' in path.lower() else 0
        features['https_in_path'] = 1 if 'https' in path.lower() else 0
        
        # Suspicious patterns
        features['ip_address'] = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url) else 0
        features['at_symbol'] = 1 if '@' in url else 0
        features['double_slash_redirect'] = 1 if '//' in url[7:] else 0
        features['prefix_suffix'] = 1 if '-' in domain else 0
        
        # SSL/Security
        features['ssl_final_state'] = 1 if url.startswith('https') else 0
        features['having_sub_domain'] = 1 if len(subdomains) > 1 else 0
        
        # Domain registration
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                domain_age = (datetime.now() - creation_date).days
                features['domain_age'] = domain_age
            else:
                features['domain_age'] = -1
        except:
            features['domain_age'] = -1
        
        # URL tokens
        features['suspicious_words'] = sum(1 for word in ['login', 'signin', 'verify', 'secure', 'account', 'password', 'credential', 'confirm', 'update'] if word in url.lower())
        features['suspicious_tld'] = 1 if ext.suffix.lower() in ['zip', 'review', 'country', 'kim', 'cricket', 'science', 'work', 'party', 'gq', 'link', 'bid', 'ws', 'top', 'ml'] else 0
        
        # Request based features
        try:
            response = requests.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form analysis
            forms = soup.find_all('form')
            features['has_form'] = 1 if forms else 0
            features['external_form_action'] = 0
            for form in forms:
                action = form.get('action', '')
                if action and not action.startswith('/') and not action.startswith(domain):
                    features['external_form_action'] = 1
                    break
            
            # Links analysis
            links = soup.find_all('a')
            external_links = 0
            for link in links:
                href = link.get('href', '')
                if href and not href.startswith('/') and not href.startswith(domain):
                    external_links += 1
            features['external_links_ratio'] = external_links / len(links) if links else 0
            
        except:
            features['has_form'] = 0
            features['external_form_action'] = 0
            features['external_links_ratio'] = 0
        
        # DNS features
        try:
            dns = socket.gethostbyname(domain)
            features['dns_record'] = 1
        except:
            features['dns_record'] = 0
            
        # Add more features here
        features['label'] = label
        
    except Exception as e:
        print(f"Error extracting features for {url}: {str(e)}")
        return None
    
    return features

# Sample phishing URLs (expanded)
phishing_urls = [
    'http://evil-site.com/login.php',
    'http://paypal-secure.phishing.com/login',
    'http://banking.secure-login.com/verify',
    'http://account-verify.suspicious.net/confirm',
    'http://login.fake-bank.com/secure',
    'http://security.malicious.org/update',
    'http://verification.scam.com/check',
    'http://suspicious.site.com/validate',
    'http://confirm-account.fake.net/verify',
    'http://secure.phishing.org/login',
    'http://login.secure-update.com/verify',
    'http://account.verification-required.net/login',
    'http://secure-signin.suspicious.org/validate',
    'http://verify-account.malicious.com/check',
    'http://banking-secure.phishing.net/confirm',
    'http://update-account.scam.org/verify',
    'http://security-check.fake.com/validate',
    'http://account-update.malicious.net/login',
    'http://verify-now.suspicious.com/check',
    'http://secure-access.phishing.org/confirm'
]

# Sample legitimate URLs (expanded)
legitimate_urls = [
    'https://www.google.com',
    'https://www.facebook.com',
    'https://www.amazon.com',
    'https://www.microsoft.com',
    'https://www.apple.com',
    'https://www.twitter.com',
    'https://www.linkedin.com',
    'https://www.github.com',
    'https://www.netflix.com',
    'https://www.spotify.com',
    'https://www.instagram.com',
    'https://www.youtube.com',
    'https://www.reddit.com',
    'https://www.wikipedia.org',
    'https://www.yahoo.com',
    'https://www.ebay.com',
    'https://www.paypal.com',
    'https://www.dropbox.com',
    'https://www.wordpress.com',
    'https://www.pinterest.com'
]

print("Extracting features from URLs...")

# Create feature vectors
feature_vectors = []

# Add phishing URLs (label 1)
for url in phishing_urls:
    features = extract_features_for_training(url, 1)
    if features:
        feature_vectors.append(features)

# Add legitimate URLs (label 0)
for url in legitimate_urls:
    features = extract_features_for_training(url, 0)
    if features:
        feature_vectors.append(features)

print(f"Successfully extracted features from {len(feature_vectors)} URLs")

# Convert to DataFrame
df = pd.DataFrame(feature_vectors)

# Handle missing values
df = df.fillna(-1)

# Separate features and labels
X = df.drop('label', axis=1)
y = df['label']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest model with more trees and better parameters
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=4,
    class_weight='balanced',
    random_state=42
)
model.fit(X_train, y_train)

# Save feature order
feature_order = list(X.columns)
with open('feature_order.pkl', 'wb') as f:
    pickle.dump(feature_order, f)

# Save the model
with open('phishing_model_new.pkl', 'wb') as f:
    pickle.dump(model, f)

# Print model evaluation
print("\nModel Evaluation:")
print("Training Score:", model.score(X_train, y_train))
print("Testing Score:", model.score(X_test, y_test))

# Print feature importances
importances = pd.DataFrame({
    'feature': feature_order,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print("\nTop 10 Most Important Features:")
print(importances.head(10)) 