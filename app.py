# app.py
from flask import Flask, render_template, request, jsonify
import joblib
import warnings
from feature_extractor import URLFeatureExtractor
from utils import convert_numpy_types, NumpyEncoder, get_domain_info

# Suppress sklearn warnings
warnings.filterwarnings('ignore', category=UserWarning)

app = Flask(__name__)
app.json_encoder = NumpyEncoder

# Load the trained model and scaler
try:
    model = joblib.load('best_phishing_model.pkl')
    scaler = joblib.load('scaler.pkl')
    feature_names = joblib.load('feature_names.pkl')
    print("✅ Models loaded successfully!")
    print(f"✅ Model type: {type(model).__name__}")
    print(f"✅ Features count: {len(feature_names)}")
except Exception as e:
    print(f"❌ Error loading models: {e}")
    model = None
    scaler = None
    feature_names = []

# Initialize feature extractor
feature_extractor = URLFeatureExtractor()

def analyze_suspicious_features(features):
    """Analyze which features are contributing to phishing detection"""
    suspicious_indicators = []
    
    # Don't show DNS failure for known legitimate domains
    if features.get('dns_resolves', 0) == 0 and features.get('KnownLegitimate', 0) == 0:
        suspicious_indicators.append("Domain does not exist")
    
    if features.get('SuspiciousTLD', 0) == 1:
        suspicious_indicators.append("Suspicious domain extension")
    
    # Only show URL shortener if it's not a known legitimate domain
    if features.get('UrlShortener', 0) == 1 and features.get('KnownLegitimate', 0) == 0:
        suspicious_indicators.append("URL shortening service")
    
    if features.get('PhishingKeywords', 0) > 2:
        suspicious_indicators.append(f"Multiple phishing keywords ({features['PhishingKeywords']})")
    
    if features.get('BrandInSubdomain', 0) == 1:
        suspicious_indicators.append("Brand name in subdomain")
    
    if features.get('EmbeddedBrandName', 0) == 1:
        suspicious_indicators.append("Suspicious brand embedding")
    
    if features.get('IpAddress', 0) == 1:
        suspicious_indicators.append("Uses IP address instead of domain")
    
    if features.get('NoHttps', 0) == 1:
        suspicious_indicators.append("No HTTPS encryption")
    
    if features.get('RandomString', 0) == 1:
        suspicious_indicators.append("Random-looking domain name")
    
    return suspicious_indicators

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        if model is None or scaler is None:
            return jsonify({'error': 'Model not loaded properly'}), 500
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400
            
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        print(f"🔍 Analyzing URL: {url}")
        
        # Extract features from URL and content
        features = feature_extractor.extract_all_features(url)
        
        if features is None:
            return jsonify({'error': 'Error processing URL'}), 400
        
        # Check if we should override the model prediction
        should_override = False
        override_reason = ""
        
        # Force legitimate for high-confidence domains
        domain_info = get_domain_info(url)
        if feature_extractor.should_force_legitimate(domain_info):
            should_override = True
            override_reason = "High-confidence legitimate domain"
            print(f"🎯 OVERRIDE: Force legitimate for {domain_info['registered_domain']}")
        
        # Also check if it's in the legitimate domains list
        elif features.get('KnownLegitimate', 0) == 1:
            should_override = True
            override_reason = "Known legitimate domain"
            print(f"🎯 OVERRIDE: Known legitimate domain {domain_info['registered_domain']}")
        
        # Convert features to array in correct order
        feature_array = [features[feature] for feature in feature_names]
        
        print(f"📊 Features extracted: {len(feature_array)}")
        
        # Scale features (suppress warnings)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            feature_array_scaled = scaler.transform([feature_array])
        
        # Make prediction
        prediction = model.predict(feature_array_scaled)[0]
        probability = model.predict_proba(feature_array_scaled)[0]
        
        # Convert to native Python types
        prediction = int(prediction)
        legitimate_prob = float(probability[0]) * 100
        phishing_prob = float(probability[1]) * 100
        
        # OVERRIDE LOGIC: If we should override, force legitimate prediction
        if should_override:
            print(f"🔧 Applying override: {override_reason}")
            prediction = 0  # Force legitimate
            # Adjust probabilities to reflect confidence in legitimate classification
            legitimate_prob = 95.0
            phishing_prob = 5.0
        
        # Get feature analysis for explanation
        feature_analysis = analyze_suspicious_features(features)
        
        result = {
            'url': url,
            'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
            'confidence': phishing_prob if prediction == 1 else legitimate_prob,
            'legitimate_probability': round(legitimate_prob, 2),
            'phishing_probability': round(phishing_prob, 2),
            'features_used': len(feature_names),
            'suspicious_indicators': feature_analysis,
            'is_known_legitimate': features.get('KnownLegitimate', 0) == 1,
            'override_applied': should_override,
            'override_reason': override_reason if should_override else None
        }
        
        # Convert all numpy types
        result = convert_numpy_types(result)
        
        print(f"✅ Prediction: {result['prediction']} (Confidence: {result['confidence']:.2f}%)")
        if feature_analysis:
            print(f"🔍 Suspicious indicators: {', '.join(feature_analysis)}")
        if should_override:
            print(f"🔧 Override applied: {override_reason}")
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Prediction error: {str(e)}")
        return jsonify({'error': f'Prediction error: {str(e)}'}), 500

@app.route('/api/health')
def health_check():
    status = 'healthy' if model is not None else 'unhealthy'
    return jsonify({
        'status': status, 
        'model_loaded': model is not None,
        'features_count': len(feature_names) if feature_names else 0
    })

if __name__ == '__main__':
    print("🚀 Starting Phishing URL Detection Server...")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)