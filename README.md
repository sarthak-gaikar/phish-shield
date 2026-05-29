# PhishShield | AI-Powered Phishing URL Detector 🛡️

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-12A5E2?style=flat-square&logo=xgboost&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-150458?style=flat-square&logo=pandas&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-7952B3?style=flat-square&logo=bootstrap&logoColor=white)
![Chart.js](https://img.shields.io/badge/Chart.js-FF6384?style=flat-square&logo=chartdotjs&logoColor=white)

PhishShield is a premium, state-of-the-art web application that leverages advanced Machine Learning and real-time heuristics to identify phishing websites and protect users from cyber threats. With a custom-trained **XGBoost** model achieving **98.85% accuracy**, PhishShield analyzes URL structure, content properties, domain reputation, and active indicators to provide instant security ratings.

---

## 🚀 Key Features

*   **Real-time Scan & Analysis**: Instantly inputs a URL, analyzes its structures, scrapes content, and predicts its safety status in under 2 seconds.
*   **48-Feature Deep Inspection**: Extracts a vast suite of features spanning structural, network-based, and content-based signals.
*   **Whitelisting & Overrides**: Includes high-confidence whitelisting rules for verified global and regional domains to minimize false positives.
*   **Dual-Engine Feature Extractor**:
    *   **URL Heuristics Engine**: Analyzes hostname structures, character distributions, subdomains, sensitive keywords, TLD risk, and brand embedding.
    *   **Content Scraper Engine**: Fetches active page HTML, checks form actions, SSL status, popup presence, iframe integration, and external-to-internal link ratios.
*   **Interactive ML Dashboard**: Built-in comparisons and visual metrics showcasing the performance of different models on a dataset of **10,000 URLs**.

---

## 📁 Repository Structure

```text
PhishShield-v2/
├── app.py                      # Flask RESTful API server & prediction handler
├── feature_extractor.py        # URL heuristics & brand spoofing detection
├── content_analyzer.py         # Requests & BeautifulSoup-based HTML scraper
├── utils.py                    # Helper functions (entropy calculation, DNS lookup, native type conversion)
├── phishing_model_training.py  # End-to-end model training, validation & comparison pipeline
├── requirements.txt            # Python dependencies
├── phishing_dataset.csv        # Dataset used to train models
├── model_comparison_results.csv# Saved metrics from model comparison
│
├── static/                     # Frontend assets
│   ├── css/
│   │   └── style.css           # Modern, custom CSS (glassmorphism, vibrant colors, premium dark elements)
│   └── js/
│       └── script.js           # Chart.js visualization, custom progress bar animations, AJAX requests
│
├── templates/
│   └── index.html              # HTML5 responsive UI template (Bootstrap 5, Chart.js, FontAwesome)
│
├── best_phishing_model.pkl     # Serialized XGBoost model (98.85% accuracy)
├── scaler.pkl                  # StandardScaler for feature scaling
├── feature_names.pkl           # Saved list of features matching training sequence
└── all_models_results.pkl      # Saved performance results for Naive Bayes, RF, SVM, XGBoost
```

---

## 📊 Machine Learning Model Comparison

The machine learning pipeline evaluates four major models using a stratified 80/20 train/test split. **XGBoost** is deployed in production due to its exceptional accuracy, precision, and robust generalization.

| Model | Accuracy | Precision | Recall | F1-Score | CV Score (5-Fold) | Training Time | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 🚀 **XGBoost** | **98.85%** | **98.80%** | **98.90%** | **98.85%** | **98.66%** | **45s** | **Active (Prod)** |
| 🌲 **Random Forest** | 98.15% | 98.29% | 98.00% | 98.15% | 97.85% | 38s | Backup |
| ⛓️ **SVM** | 96.90% | 96.16% | 97.70% | 96.92% | 96.14% | 52s | Backup |
| 📊 **Naive Bayes** | 85.85% | 93.67% | 76.90% | 84.46% | 84.33% | 12s | Backup |

### 🎯 Top 5 Most Important Features (XGBoost)

1.  **`PctExtNullSelfRedirectHyperlinksRT` (44.39%)**: The percentage of external links, null links (`#`), or self-redirects inside scripts or anchor tags.
2.  **`IpAddress` (10.20%)**: Indicator if the URL uses a direct IP instead of a registered domain name (common phishing signature).
3.  **`PctExtHyperlinks` (6.39%)**: Ratio of external hyperlinks to total hyperlinks on the webpage.
4.  **`TildeSymbol` (4.46%)**: Presence of a `~` in the URL path, often referencing direct user directories on vulnerable servers.
5.  **`FrequentDomainNameMismatch` (3.85%)**: Occurrence of different domains inside resources, images, or anchor elements compared to the host domain.

---

## 🛠️ Installation & Setup

Follow these steps to set up and run PhishShield locally.

### Prerequisites
*   Python 3.8 or higher installed on your system.

### 1. Clone & Navigate
```bash
git clone <repository_url>
cd PhishShield-v2
```

### 2. Install Dependencies
Install all required libraries using the requirements file:
```bash
pip install -r requirements.txt
```

### 3. (Optional) Re-run Model Training
If you want to re-train the models and generate updated pickles using the training dataset (`phishing_dataset.csv`):
```bash
python phishing_model_training.py
```
This will train all four models, display performance comparison charts, and save the optimized `best_phishing_model.pkl`, `scaler.pkl`, `feature_names.pkl`, and `all_models_results.pkl`.

### 4. Run the Web App
Start the Flask development server:
```bash
python app.py
```
The server will boot up and be accessible locally:
*   **Local URL**: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🔌 API Endpoints

PhishShield provides a fast, lightweight RESTful API for integrations.

### 1. Scan a URL
Predict whether a URL is legitimate or a phishing threat.

*   **Endpoint**: `/predict`
*   **Method**: `POST`
*   **Headers**: `Content-Type: application/json`
*   **Request Body**:
    ```json
    {
      "url": "http://secure-login-bankupdate.gq/login.php"
    }
    ```
*   **Successful Response (Phishing Threat)**:
    ```json
    {
      "url": "http://secure-login-bankupdate.gq/login.php",
      "prediction": "Phishing",
      "confidence": 99.85,
      "legitimate_probability": 0.15,
      "phishing_probability": 99.85,
      "features_used": 48,
      "suspicious_indicators": [
        "Domain does not exist",
        "Suspicious domain extension",
        "Multiple phishing keywords (2)",
        "No HTTPS encryption"
      ],
      "is_known_legitimate": false,
      "override_applied": false,
      "override_reason": null
    }
    ```

### 2. Service Health
Check the load status of the AI models and the endpoint health.

*   **Endpoint**: `/api/health`
*   **Method**: `GET`
*   **Successful Response**:
    ```json
    {
      "status": "healthy",
      "model_loaded": true,
      "features_count": 48
    }
    ```

---

## 🔒 Security Recommendations Integrated

PhishShield doesn't just block; it explains why. The frontend provides context-aware guidance for detected threats:
1.  **Do not enter any personal or banking credentials**.
2.  **Avoid downloading files** or accepting cookies from suspicious extensions.
3.  **Confirm TLDs** (e.g., watch out for `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz` for transactional portals).
4.  **Confirm brand embedding** (e.g., seeing `paypal` in a subdomain like `paypal.verify-login.online` is a high indicator of threat).
