import xgboost as xgb
import re
import requests
import base64
import time
import pandas as pd
import xgboost as xgb
import requests
import time
import tldextract
import urllib.parse
import socket
import whois
import ssl
import datetime
from OpenSSL import crypto
import joblib
import pandas as pd
import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from nltk.tokenize import word_tokenize
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
from PIL import Image
import pytesseract
import os


#loading link detection model

link_detection_model=xgb.XGBClassifier()
link_detection_model.load_model("final_xgboost_model.json")
#link detection functions:
def normalize_url(url):
    """Ensure URL has a scheme (http/https) for consistent parsing."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url  # Default to http (will check https later)
    return url

def virus_total_check(url):
    API_KEY = 'Replace with your VirusTotal API key'  
    url_to_check = url  # Replace with the URL you want to analyze

    headers = {
        "x-apikey": API_KEY
    }

    # Step 1: Submit the URL for analysis
    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(submit_url, headers=headers, data={"url": url_to_check})

    if response.status_code != 200:
        print("[-] Error submitting URL:", response.text)
        exit()

    analysis_id = response.json()["data"]["id"]
    print(f"[+] Submitted URL. Analysis ID: {analysis_id}")

    # Step 2: Wait for analysis to complete
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        analysis_response = requests.get(analysis_url, headers=headers)
        status = analysis_response.json()["data"]["attributes"]["status"]
        if status == "completed":
            break
        print("[*] Waiting for scan to complete...")
        time.sleep(3)

    # Step 3: Get the full report of the URL
    # You need to base64 encode the URL (URL-safe, no padding) to get the final verdict
    encoded_url = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    url_report = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"

    report_response = requests.get(url_report, headers=headers)
    data = report_response.json()

    # Step 4: Interpret results
    stats = data["data"]["attributes"]["last_analysis_stats"]
    categories = data["data"]["attributes"]["categories"]

    print("\n🛡️ Scan Summary:")
    print(f"Malicious: {stats['malicious']}")
    print(f"Suspicious: {stats['suspicious']}")
    print(f"Harmless: {stats['harmless']}")
    print(f"Undetected: {stats['undetected']}")
    print(f"Timeout: {stats['timeout']}")

    print("\n📊 Vendor Verdicts:")
    for vendor, category in categories.items():
        print(f"{vendor}: {category}")

    # Optional: Flagging based on results
    if stats["malicious"] > 0 or "phishing" in categories.values():
        print("\n🚨 The URL is flagged as *malicious or phishing*.")
        return stats['malicious']
    else:
        print("\n✅ The URL appears to be *legitimate* or harmless.")
        return 0
    
#this is the feature extraction part for the input url with associated helper functions

# ======================================================================
# STEP 1: Helper Functions (DNS, WHOIS, SSL)
# ======================================================================

def check_dns_record(domain):
    """Check if DNS record exists (returns 1 if valid, 0 otherwise)."""
    try:
        socket.gethostbyname(domain)
        return 1
    except:
        return 0

def get_domain_age(domain):
    """Get domain age in days using WHOIS (returns age or 365 if unknown)."""
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.datetime.now() - creation_date).days
        return max(age, 1)  # Minimum 1 day to avoid zero
    except:
        return 365  # Default if WHOIS fails

def validate_https(url):
    """Check HTTPS validity (returns 1 if valid, 0 if insecure/expired)."""
    try:
        hostname = urllib.parse.urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Check expiry
                expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if expiry_date < datetime.datetime.now():
                    return 0
                return 1
    except:
        return 0

# ======================================================================
# STEP 2: Feature Extraction (Now with Real Data)
# ======================================================================

def extract_url_features(url):
    # Normalize URL (ensure scheme)
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    
    # Extract main domain (e.g., "google.com" from "sub.google.com")
    ext = tldextract.extract(domain)
    main_domain = f"{ext.domain}.{ext.suffix}"

    features = {
        'Have_IP': 1 if domain.replace('.', '').isdigit() else 0,
        'https_Domain': 1 if parsed.scheme == 'https' else 0,
        'URL_Length': len(url),
        'Have_At': 1 if '@' in url else 0,
        'URL_Depth': parsed.path.count('/'),
        'Prefix/Suffix': 1 if '-' in ext.domain else 0,
        'DNS_Record': check_dns_record(main_domain),  # Real DNS lookup
        'Domain_Age': get_domain_age(main_domain),   # Real WHOIS age
        'Redirection': 1 if '//' in parsed.path else 0,  # Check path only
        'Web_Traffic': 0,  # Set to 0 (avoid mock values)
        'Web_Forwards': 0,
        'TinyURL': 1 if len(url) < 20 else 0,  # Adjust threshold to 30
        'Domain_End': 1 if validate_https(url) else 0,
    }
    return features
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import socket

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import socket
import requests

import requests

def check_url_connectivity(url, timeout=(5, 10)):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        # Make the request
        response = requests.get(url, headers=headers, timeout=timeout)
        
        if response.status_code == 200:
            return True, "URL is reachable"
        
        elif response.status_code in [401, 403, 503]:
            # Do not treat these as phishing, just warn for manual review
            return True, f"URL responded with {response.status_code} (Access Restricted or Temporarily Unavailable)"
        
        else:
            # Other unexpected status codes
            return False, f"URL returned unexpected status code: {response.status_code}"

    except requests.exceptions.ReadTimeout:
        return False, "Read operation timed out"
    
    except requests.exceptions.ConnectTimeout:
        return False, "Connection timed out"
    
    except requests.exceptions.ConnectionError:
        return False, "Failed to establish a connection"
    
    except requests.exceptions.RequestException as e:
        return False, f"Request failed: {str(e)}"


        
def predict_phishing(url):
    url=normalize_url(url)
    features = extract_url_features(url)
    features_df = pd.DataFrame([features])
    is_reachable, reason = check_url_connectivity(url, timeout=5)
    print(f"[DEBUG] Connectivity check: {is_reachable} - {reason}")

    if not is_reachable:
        return {
            'url': url,
            'prediction': 'Suspicious',
            'confidence': None,
            'reason': reason
        }

    
    xgb_prob = link_detection_model.predict_proba(features_df)[0][1]
    print("XGBoost probability:", xgb_prob)

    vt_malicious = virus_total_check(url)
    print("VirusTotal score:", vt_malicious)

    if vt_malicious >= 2:
        label = "Phishing"
    elif vt_malicious >= 1 or xgb_prob >= 0.997:
        label = "Suspicious"
    else:
        label = "Legitimate"

    return {
    'url': url,
    'prediction': label,
    'confidence': round(float(xgb_prob), 4),
    'reason': "URL is safe, and legitimate"
}


#loading message detection model
# Load the model, vectorizer, and encoder
model = joblib.load("spam_message_model.pkl")
tfidf = joblib.load("tfidf_vectorizer.pkl")
le = joblib.load("label_encoder.pkl")
stemmer = PorterStemmer()
stop_words = set(stopwords.words('english'))

def predict_message(message):
    msg = re.sub('[^A-Za-z]', ' ', message).lower()
    words = word_tokenize(msg)
    filtered = [stemmer.stem(word) for word in words if word not in stop_words]
    preprocessed = ' '.join(filtered)
    vectorized = tfidf.transform([preprocessed]).toarray()
    pred = model.predict(vectorized)[0]
    return le.inverse_transform([pred])[0]

def analyze_message_with_links(message):
    urls = extract_urls(message)
    phishing_results = []

    # Check each URL for phishing
    for url in urls:
        url=normalize_url(url)
        result = predict_phishing(url)
        phishing_results.append({'url': url, 'result': result})

    # Remove URLs from the message for clean text classification
    clean_text = re.sub(r'https?://[^\s]+', '', message)

    # Classify the clean message
    message_label = predict_message(clean_text.strip())

    return {
        'original_message': message,
        'cleaned_message': clean_text.strip(),
        'message_prediction': message_label,
        'urls_detected': phishing_results
    }
import re

def extract_urls(text):
    # Simple regex for URLs
    url_regex = r'(https?://[^\s]+)'
    return re.findall(url_regex, text)

#upload ss
def extract_text_from_image(image_path):
    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        return text
    except Exception as e:
        print("OCR failed:", e)
        return ""

def analyze_image(image_file_path):
    extracted_text = extract_text_from_image(image_file_path)
    print(f"[OCR Extracted Text]:\n{extracted_text}")
    if not extracted_text.strip():
        return {
            'text': '',
            'message_prediction': 'Unreadable/No Text Found',
            'urls_detected': []
        }
    result = analyze_message_with_links(extracted_text)
    result['extracted_text'] = extracted_text
    return result

