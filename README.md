<<<<<<< HEAD
# PHISHSHIELD 🛡️

A Flask-based web application that uses machine learning to detect phishing websites in real-time.

---

## 🚀 Features

* **Real-Time Detection:** Enter a URL and get an instant prediction on whether it's legitimate or a phishing attempt.
* **ML-Powered:** Utilizes a machine learning model trained on a phishing dataset.
* **Feature Extraction:** Analyzes various features of a URL to make an accurate prediction.
* **Simple Web Interface:** Easy-to-use interface built with HTML, CSS, and JavaScript.

---

## 🛠️ How It Works

The application follows a simple machine learning pipeline:

1.  **Input:** A user submits a URL through the web interface.
2.  **Feature Extraction:** The `feature_extractor.py` script parses the URL and extracts key features (e.g., URL length, presence of '@' symbol, IP address in domain, etc.).
3.  **Prediction:** The pre-trained machine learning model (`best_phishing_model.pkl`) and scaler (`scaler.pkl`) are loaded. The extracted features are scaled and fed into the model.
4.  **Output:** The model predicts whether the site is "Legitimate" or "Phishing," and the result is displayed to the user.

---

## 💻 Setup and Installation

Follow these steps to get the project running on your local machine.

### 1. Prerequisites

* Python 3.7+
* pip (Python package installer)

### 2. Clone the Repository

```bash
git clone [https://github.com/sarthak-gaikar/phish-shield.git](https://github.com/sarthak-gaikar/phish-shield.git)
cd phish-shield
````

### 3. Create a Virtual Environment

It's highly recommended to use a virtual environment to manage dependencies.

```bash
# For Windows
python -m venv venv
.\venv\Scripts\activate

# For macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### 4\. Install Dependencies

Install all the required Python packages using the `requirements.txt` file.

=======
# PhishShield | AI-Powered Phishing URL Detector 🛡️

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
>>>>>>> f95a4fa (Update README.md)
```bash
pip install -r requirements.txt
```

<<<<<<< HEAD
### 5\. Train the Model (Important\!)

The model files (`.pkl`), dataset (`.csv`), and scaler are included in the `.gitignore` and are not uploaded to GitHub. You must run the training script to generate them first.

```bash
python phishing_model_training.py
```

This will use `phishing_dataset.csv` to train the models and save `best_phishing_model.pkl`, `scaler.pkl`, and other result files.

-----

## 🏃‍♂️ How to Run the Application

Once the setup is complete and the models are trained:

1.  **Start the Flask Server:**

    ```bash
    flask run
    ```

    *Alternatively, you can run `python app.py`.*

2.  **Open in Browser:**
    Open your web browser and navigate to:
    [http://127.0.0.1:5000](https://www.google.com/search?q=http://127.0.0.1:5000)

You should now see the PhishShield web interface, ready to test URLs.

-----

## 📁 Project File Structure

Here is a brief overview of the key files in the project:

```
├── app.py                      # Main Flask application file (handles routing, prediction)
├── phishing_model_training.py  # Script to train and save the ML model
├── feature_extractor.py        # Contains functions to extract features from URLs
├── utils.py                    # Utility functions (if any)
├── requirements.txt            # List of Python dependencies
├── .gitignore                  # Files to be ignored by Git (like models, datasets)
|
├── templates/
│   └── index.html              # Frontend HTML page
|
├── static/
│   ├── css/style.css           # CSS for styling
│   └── js/script.js            # JavaScript for frontend logic
|
├── phishing_dataset.csv        # (Not on GitHub) Dataset used for training
├── best_phishing_model.pkl     # (Not on GitHub) The saved trained model
└── scaler.pkl                  # (Not on GitHub) The saved scaler object
```

-----

## 🔧 Technologies Used

  * **Backend:** Flask
  * **Machine Learning:** Scikit-learn, Pandas
  * **Frontend:** HTML, CSS, JavaScript

-----

## 📄 License

This project is open-source.
=======
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
>>>>>>> f95a4fa (Update README.md)
