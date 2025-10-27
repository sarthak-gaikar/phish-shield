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

```bash
pip install -r requirements.txt
```

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
