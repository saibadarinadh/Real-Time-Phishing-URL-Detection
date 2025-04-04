import re
import socket
import ssl
import time
import whois
import requests
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import tldextract
import dns.resolver
import spf
from ipwhois import IPWhois
from joblib import load
from tensorflow.keras.models import load_model
import os

# === Load your trained models ===
scaler = load("C:/Users/Badari/Downloads/ris/final_new/saved_models/scaler.joblib")
xgb_model = load("C:/Users/Badari/Downloads/ris/final_new/saved_models/xgboost_model.joblib")
lstm_model = load_model("C:/Users/Badari/Downloads/ris/final_new/saved_models/lstm_model.h5")
REQUIRED_FEATURES = list(scaler.feature_names_in_)

CHARS = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']

# === Real-time data functions ===
def time_response(domain):
    try:
        start = time.time()
        socket.gethostbyname(domain)
        return round((time.time() - start) * 1000)
    except:
        return 0

def check_spf(domain):
    try:
        result = spf.check2(i='127.0.0.1', s='test@' + domain, h=domain)
        return 1 if result[0] == 'pass' else 0
    except:
        return 0

def get_ttl(domain):
    try:
        return dns.resolver.resolve(domain, 'A').rrset.ttl
    except:
        return 0

def check_ssl_validity(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            return 1 if s.getpeercert() else 0
    except:
        return 0

def is_indexed_by_google(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        query = f"https://www.google.com/search?q=site:{url}"
        response = requests.get(query, headers=headers, timeout=5)
        return 0 if "did not match any documents" in response.text else 1
    except:
        return 0

def get_asn_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        result = IPWhois(ip).lookup_rdap()
        return int(result.get("asn", 0))
    except:
        return 0

def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        now = pd.Timestamp.utcnow()
        created = info.creation_date
        expires = info.expiration_date
        if isinstance(created, list): created = created[0]
        if isinstance(expires, list): expires = expires[0]
        creation = pd.Timestamp(created) if created else None
        expiration = pd.Timestamp(expires) if expires else None
        age = (now - creation).days if creation else 0
        exp = (expiration - now).days if expiration else 0
        return max(age, 0), max(exp, 0)
    except:
        return 0, 0

def resolve_dns(domain, record_type):
    try:
        return len(dns.resolver.resolve(domain, record_type))
    except:
        return 0

def get_redirect_count(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return len(response.history)
    except:
        return 0

# === Main feature extraction ===
def count_chars(text):
    return [text.count(c) for c in CHARS]

def extract_features_from_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    ext = tldextract.extract(url)
    suffix = ext.suffix
    file = path.split("/")[-1]

    features = {}

    # URL
    for c in CHARS:
        features[f'qty_{c if c != " " else "space"}_url'] = url.count(c)
    features['qty_tld_url'] = len(suffix)
    features['length_url'] = len(url)

    # Domain
    for c in CHARS:
        features[f'qty_{c if c != " " else "space"}_domain'] = domain.count(c)
    features['qty_vowels_domain'] = sum(domain.count(v) for v in 'aeiou')
    features['domain_length'] = len(domain)
    features['domain_in_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
    features['server_client_domain'] = 1 if 'server' in domain or 'client' in domain else 0

    # Directory
    for c in CHARS:
        features[f'qty_{c if c != " " else "space"}_directory'] = path.count(c)
    features['directory_length'] = len(path)

    # File
    for c in CHARS:
        features[f'qty_{c if c != " " else "space"}_file'] = file.count(c)
    features['file_length'] = len(file)

    # Params
    for c in CHARS:
        features[f'qty_{c if c != " " else "space"}_params'] = query.count(c)
    features['params_length'] = len(query)
    features['tld_present_params'] = 1 if suffix in query else 0
    features['qty_params'] = len(query.split('&')) if query else 0

    # Real-time fields
    features['email_in_url'] = 1 if re.search(r'\w+@\w+\.\w+', url) else 0
    features['time_response'] = time_response(domain)
    features['domain_spf'] = check_spf(domain)
    features['asn_ip'] = get_asn_ip(domain)
    features['time_domain_activation'], features['time_domain_expiration'] = get_domain_age(domain)
    features['qty_ip_resolved'] = resolve_dns(domain, 'A')
    features['qty_nameservers'] = resolve_dns(domain, 'NS')
    features['qty_mx_servers'] = resolve_dns(domain, 'MX')
    features['ttl_hostname'] = get_ttl(domain)
    features['tls_ssl_certificate'] = check_ssl_validity(domain)
    features['qty_redirects'] = get_redirect_count(url)
    features['url_google_index'] = is_indexed_by_google(url)
    features['domain_google_index'] = is_indexed_by_google(domain)
    features['url_shortened'] = 1 if re.search(r'bit\.ly|goo\.gl|t\.co|tinyurl', url) else 0

    final_features = {f: features.get(f, 0) for f in REQUIRED_FEATURES}
    return pd.DataFrame([final_features])

# === Prediction ===
def predict_url(url):
    try:
        features = extract_features_from_url(url)
        scaled = scaler.transform(features)
        xgb_out = xgb_model.apply(scaled)
        lstm_input = np.reshape(xgb_out, (xgb_out.shape[0], xgb_out.shape[1], 1))
        pred = lstm_model.predict(lstm_input)
        label = int(pred[0][0] > 0.5)
        print(f"\n🔍 URL: {url}")
        print(f"🧠 Prediction: {'Phishing ⚠️' if label == 1 else 'Legitimate ✅'}")
        print(f"📊 Confidence: {pred[0][0]:.4f}")

        # Optional logging
        features["prediction"] = label
        features["confidence"] = float(pred[0][0])
        features.to_csv("real_time_predictions.csv", mode='a', index=False, header=not os.path.exists("real_time_predictions.csv"))

    except Exception as e:
        print(f"❌ Error: {e}")

# === CLI Run ===
if __name__ == "__main__":
    user_url = input("🔗 Enter a URL to analyze: ").strip()
    predict_url(user_url)
