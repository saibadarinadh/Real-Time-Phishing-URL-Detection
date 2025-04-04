# 🛡️ Real-Time Phishing URL Detection (Hybrid XGBoost + LSTM)

This repository contains a complete web-based solution for detecting phishing URLs using a hybrid machine learning model combining XGBoost and LSTM. The system performs real-time feature extraction, analysis, and prediction, offering a user-friendly web interface and deep backend intelligence.

---

## 📂 Dataset Source

We use the public [Phishing Dataset by Grega Vrbancic](https://github.com/GregaVrbancic/Phishing-Dataset), specifically:

- `dataset_full.csv`: 88,647 URLs with 111 features (58,000 legitimate, 30,647 phishing)

---

## 🧠 Model Architecture

This is a **hybrid two-stage model**:

### 1. **XGBoost Classifier**
- Learns feature importance and generates tree-based embeddings.
- Output from `.apply()` is used as input for LSTM.

### 2. **LSTM Neural Network**
- Takes transformed leaf indices from XGBoost.
- Learns hidden temporal/structural patterns for final classification.

> ⚙️ Trained using TensorFlow, Scikit-learn, XGBoost on preprocessed features from the dataset.

---

## 🚀 Real-Time Web Interface

The web application is built using **Flask** and allows users to:

- 🔗 Input any URL
- ⚙️ Extract all 111 features in real-time
- 📊 Predict if the URL is phishing or legitimate
- 📋 View all extracted features in a table

### 🌐 Live Features Extracted:
- DNS Response Time (`time_response`)
- SPF Record Check (`domain_spf`)
- TTL Value (`ttl_hostname`)
- SSL Certificate Validity (`tls_ssl_certificate`)
- Redirects, A/MX/NS Records, ASN, WHOIS (domain age)
- Google Index Check for domain and full URL

---

## 📦 File Structure

```
├── app.py                  # Flask web app
├── templates/
│   └── index.html          # Web UI
├── saved_models/
│   ├── xgboost_model.joblib
│   ├── lstm_model.h5
│   └── scaler.joblib
├── dataset_full.csv        # Original dataset
├── README.md
```

---

## 🧪 How to Run

1. **Clone the repo:**
```bash
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector
```

2. **Install requirements:**
```bash
pip install -r requirements.txt
```

3. **Run the app:**
```bash
python app.py
```

4. **Visit in browser:**
```
http://127.0.0.1:5000
```

---

## 📈 Output Example

- **Input URL**: `https://chatgpt.com`
- **Prediction**: `Legitimate ✅`
- **Confidence**: `0.88`
- **111 extracted features displayed**

---

## 🧩 Future Enhancements

- Add user authentication & history logging
- Deploy on cloud (Render, Heroku, AWS)
- Add feature importances visualization
- Provide CSV download for feature data

---

## 📚 Credits

- Dataset: [Grega Vrbancic GitHub](https://github.com/GregaVrbancic/Phishing-Dataset)
- XGBoost: https://xgboost.ai/
- LSTM: TensorFlow/Keras
- Flask: https://flask.palletsprojects.com/
- DNS/WHOIS/IP tools: `dnspython`, `pyspf`, `ipwhois`, `python-whois`

---


