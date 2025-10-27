import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.metrics import roc_curve, auc

# Load trained models
models = joblib.load("all_models_results.pkl")
print("Loaded models:", list(models.keys()))

# Load dataset
df = pd.read_csv("phishing_dataset.csv")  # replace with your CSV path

# Preprocess features and target
X = df.drop(columns=['id', 'CLASS_LABEL'])
y = LabelEncoder().fit_transform(df['CLASS_LABEL'])  # encode -1/1 to 0/1

# Normalize features
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# Plot ROC curves
plt.figure(figsize=(8,6))

for name, model_dict in models.items():
    model = model_dict['model']  # extract actual sklearn model

    # Predict probabilities or scale decision_function
    if hasattr(model, "predict_proba"):
        y_pred_prob = model.predict_proba(X_test)[:,1]
    else:
        y_score = model.decision_function(X_test)
        y_pred_prob = MinMaxScaler().fit_transform(y_score.reshape(-1,1)).ravel()
    
    fpr, tpr, _ = roc_curve(y_test, y_pred_prob)
    roc_auc = auc(fpr, tpr)
    
    plt.plot(fpr, tpr, lw=2, label=f"{name} (AUC = {roc_auc:.2f})")

plt.plot([0, 1], [0, 1], 'k--', alpha=0.5)
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curves of Phishing Detection Models")
plt.legend(loc="lower right")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig("roc_curves_all_models.png", dpi=300)
plt.show()

print("✅ ROC curve image saved as 'roc_curves_all_models.png'")
