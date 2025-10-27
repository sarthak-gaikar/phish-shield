# phishing_model_training.py

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_score, recall_score, f1_score
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
import joblib
import warnings
warnings.filterwarnings('ignore')

# Set style for better visualizations
plt.style.use('seaborn-v0_8')

class PhishingModelTrainer:
    def __init__(self, data_path):
        self.data_path = data_path
        self.df = None
        self.X = None
        self.y = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.scaler = None
        self.X_train_scaled = None
        self.X_test_scaled = None
        self.results = {}
        self.best_model = None
        self.best_model_name = None
        
    def load_data(self):
        """Load and explore the dataset"""
        print("📊 Loading dataset...")
        try:
            self.df = pd.read_csv(self.data_path)
            print(f"✅ Dataset loaded successfully: {self.df.shape}")
        except FileNotFoundError:
            print("❌ File not found. Please check the file path.")
            return False
        except Exception as e:
            print(f"❌ Error loading file: {e}")
            return False
            
        # Display basic information
        print("\n📈 Dataset Overview:")
        print(f"Shape: {self.df.shape}")
        print(f"Columns: {len(self.df.columns)}")
        
        print("\n🔍 First 5 rows:")
        print(self.df.head())
        
        print("\n📋 Dataset Info:")
        print(self.df.info())
        
        print("\n🎯 Class Distribution:")
        class_dist = self.df['CLASS_LABEL'].value_counts()
        print(class_dist)
        
        # Plot class distribution
        plt.figure(figsize=(10, 6))
        plt.subplot(1, 2, 1)
        sns.countplot(data=self.df, x='CLASS_LABEL')
        plt.title('Class Distribution')
        plt.xlabel('Class (0: Legitimate, 1: Phishing)')
        plt.ylabel('Count')
        
        plt.subplot(1, 2, 2)
        plt.pie(class_dist.values, labels=['Legitimate', 'Phishing'], autopct='%1.1f%%', colors=['lightblue', 'lightcoral'])
        plt.title('Class Proportion')
        
        plt.tight_layout()
        plt.show()
        
        return True
    
    def preprocess_data(self):
        """Preprocess the data"""
        print("\n🔧 Preprocessing data...")
        
        # Check for missing values
        print("Missing values in each column:")
        missing_values = self.df.isnull().sum()
        print(missing_values[missing_values > 0])
        
        if missing_values.sum() > 0:
            print("🔄 Handling missing values...")
            # Fill numerical columns with median
            numerical_cols = self.df.select_dtypes(include=[np.number]).columns
            self.df[numerical_cols] = self.df[numerical_cols].fillna(self.df[numerical_cols].median())
            print("✅ Missing values handled")
        
        # Separate features and target
        self.X = self.df.drop(['id', 'CLASS_LABEL'], axis=1)
        self.y = self.df['CLASS_LABEL']
        
        print(f"✅ Features shape: {self.X.shape}")
        print(f"✅ Target shape: {self.y.shape}")
        
        # Display feature statistics
        print("\n📊 Feature Statistics:")
        print(self.X.describe())
        
    def split_and_scale_data(self):
        """Split data into train/test and scale features"""
        print("\n📊 Splitting and scaling data...")
        
        # Split the data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            self.X, self.y, test_size=0.2, random_state=42, stratify=self.y
        )
        
        print(f"✅ Training set: {self.X_train.shape}")
        print(f"✅ Testing set: {self.X_test.shape}")
        
        # Scale the features
        self.scaler = StandardScaler()
        self.X_train_scaled = self.scaler.fit_transform(self.X_train)
        self.X_test_scaled = self.scaler.transform(self.X_test)
        
        print("✅ Data scaled successfully")
    
    def train_models(self):
        """Train and evaluate all models"""
        print("\n🤖 Training models...")
        
        # Initialize models with optimized parameters
        models = {
            'Naive Bayes': GaussianNB(),
            'Random Forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42
            ),
            'XGBoost': XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='logloss'
            ),
            'SVM': SVC(
                C=1.0,
                kernel='rbf',
                gamma='scale',
                random_state=42,
                probability=True
            )
        }
        
        for name, model in models.items():
            print(f"\n{'='*60}")
            print(f"Training {name}...")
            
            # Use scaled data for SVM, original for others
            if name == 'SVM':
                X_tr = self.X_train_scaled
                X_te = self.X_test_scaled
            else:
                X_tr = self.X_train
                X_te = self.X_test
            
            # Train model
            model.fit(X_tr, self.y_train)
            
            # Make predictions
            y_pred = model.predict(X_te)
            y_pred_proba = model.predict_proba(X_te)[:, 1] if hasattr(model, 'predict_proba') else None
            
            # Calculate metrics
            accuracy = accuracy_score(self.y_test, y_pred)
            precision = precision_score(self.y_test, y_pred)
            recall = recall_score(self.y_test, y_pred)
            f1 = f1_score(self.y_test, y_pred)
            
            # Cross-validation
            cv_scores = cross_val_score(model, X_tr, self.y_train, cv=5, scoring='accuracy')
            
            # Store results
            self.results[name] = {
                'model': model,
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'predictions': y_pred,
                'probabilities': y_pred_proba
            }
            
            print(f"✅ {name} Training Completed")
            print(f"📊 Accuracy: {accuracy:.4f}")
            print(f"🎯 Precision: {precision:.4f}")
            print(f"🔍 Recall: {recall:.4f}")
            print(f"⚖️ F1-Score: {f1:.4f}")
            print(f"🔄 CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    def compare_models(self):
        """Compare model performance and select the best one"""
        print("\n📈 Comparing model performance...")
        
        # Create comparison dataframe
        comparison_data = []
        for name, result in self.results.items():
            comparison_data.append({
                'Model': name,
                'Accuracy': result['accuracy'],
                'Precision': result['precision'],
                'Recall': result['recall'],
                'F1-Score': result['f1_score'],
                'CV_Score': result['cv_mean'],
                'CV_Std': result['cv_std']
            })
        
        self.comparison_df = pd.DataFrame(comparison_data)
        self.comparison_df = self.comparison_df.sort_values('Accuracy', ascending=False)
        
        print("\n🏆 Model Comparison:")
        print(self.comparison_df.round(4))
        
        # Get the best model
        self.best_model_name = self.comparison_df.iloc[0]['Model']
        self.best_model = self.results[self.best_model_name]['model']
        
        print(f"\n🎯 Best Model: {self.best_model_name}")
        print(f"📊 Best Accuracy: {self.results[self.best_model_name]['accuracy']:.4f}")
        
        # Plot accuracy comparison
        self.plot_model_comparison()
        
        return self.best_model_name
    
    def plot_model_comparison(self):
        """Plot model comparison charts"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        
        # Accuracy comparison
        sns.barplot(data=self.comparison_df, x='Accuracy', y='Model', ax=axes[0, 0], palette='viridis')
        axes[0, 0].set_title('Model Accuracy Comparison')
        axes[0, 0].set_xlim(0, 1)
        
        # Precision, Recall, F1 comparison
        metrics_df = self.comparison_df.melt(id_vars=['Model'], 
                                           value_vars=['Precision', 'Recall', 'F1-Score'],
                                           var_name='Metric', value_name='Score')
        sns.barplot(data=metrics_df, x='Score', y='Model', hue='Metric', ax=axes[0, 1])
        axes[0, 1].set_title('Precision, Recall, and F1-Score Comparison')
        axes[0, 1].set_xlim(0, 1)
        axes[0, 1].legend(loc='lower right')
        
        # Cross-validation scores
        sns.barplot(data=self.comparison_df, x='CV_Score', y='Model', ax=axes[1, 0], palette='coolwarm')
        axes[1, 0].set_title('Cross-Validation Scores')
        axes[1, 0].set_xlim(0, 1)
        
        # Detailed metrics for best model
        best_result = self.results[self.best_model_name]
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        values = [best_result['accuracy'], best_result['precision'], 
                 best_result['recall'], best_result['f1_score']]
        
        axes[1, 1].barh(metrics, values, color=['blue', 'green', 'orange', 'red'])
        axes[1, 1].set_title(f'Detailed Metrics - {self.best_model_name}')
        axes[1, 1].set_xlim(0, 1)
        for i, v in enumerate(values):
            axes[1, 1].text(v + 0.01, i, f'{v:.4f}', va='center')
        
        plt.tight_layout()
        plt.show()
    
    def evaluate_best_model(self):
        """Detailed evaluation of the best model"""
        print(f"\n{'='*60}")
        print(f"🔍 Detailed Evaluation for Best Model: {self.best_model_name}")
        print(f"{'='*60}")
        
        best_result = self.results[self.best_model_name]
        best_predictions = best_result['predictions']
        
        # Classification Report
        print("\n📋 Classification Report:")
        print(classification_report(self.y_test, best_predictions, 
                                  target_names=['Legitimate', 'Phishing']))
        
        # Confusion Matrix
        plt.figure(figsize=(10, 8))
        cm = confusion_matrix(self.y_test, best_predictions)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Legitimate', 'Phishing'], 
                    yticklabels=['Legitimate', 'Phishing'])
        plt.title(f'Confusion Matrix - {self.best_model_name}', fontsize=14, fontweight='bold')
        plt.ylabel('Actual', fontweight='bold')
        plt.xlabel('Predicted', fontweight='bold')
        plt.show()
        
        # Feature Importance (if available)
        if hasattr(self.best_model, 'feature_importances_'):
            self.plot_feature_importance()
    
    def plot_feature_importance(self, top_n=15):
        """Plot feature importance for tree-based models"""
        if hasattr(self.best_model, 'feature_importances_'):
            print(f"\n📊 Plotting Top {top_n} Feature Importances...")
            
            feature_importance = pd.DataFrame({
                'feature': self.X.columns,
                'importance': self.best_model.feature_importances_
            }).sort_values('importance', ascending=False)
            
            plt.figure(figsize=(12, 8))
            sns.barplot(data=feature_importance.head(top_n), x='importance', y='feature', palette='rocket')
            plt.title(f'Top {top_n} Feature Importance - {self.best_model_name}', fontsize=14, fontweight='bold')
            plt.xlabel('Importance Score', fontweight='bold')
            plt.tight_layout()
            plt.show()
            
            print(f"\n🎯 Top {top_n} Most Important Features:")
            print(feature_importance.head(top_n).round(4))
    
    def save_models(self):
        """Save the trained models and scaler"""
        print("\n💾 Saving models...")
        
        # Save the best model
        joblib.dump(self.best_model, 'best_phishing_model.pkl')
        print("✅ Best model saved as 'best_phishing_model.pkl'")
        
        # Save the scaler
        joblib.dump(self.scaler, 'scaler.pkl')
        print("✅ Scaler saved as 'scaler.pkl'")
        
        # Save all models
        joblib.dump(self.results, 'all_models_results.pkl')
        print("✅ All models results saved as 'all_models_results.pkl'")
        
        # Save feature names
        joblib.dump(list(self.X.columns), 'feature_names.pkl')
        print("✅ Feature names saved as 'feature_names.pkl'")
        
        # Save comparison results as CSV
        self.comparison_df.to_csv('model_comparison_results.csv', index=False)
        print("✅ Model comparison saved as 'model_comparison_results.csv'")
    
    def run_complete_training(self):
        """Run the complete training pipeline"""
        print("🚀 Starting Phishing URL Detection Model Training Pipeline...")
        print("=" * 70)
        
        # Step 1: Load data
        if not self.load_data():
            return
        
        # Step 2: Preprocess data
        self.preprocess_data()
        
        # Step 3: Split and scale data
        self.split_and_scale_data()
        
        # Step 4: Train models
        self.train_models()
        
        # Step 5: Compare models
        self.compare_models()
        
        # Step 6: Evaluate best model
        self.evaluate_best_model()
        
        # Step 7: Save models
        self.save_models()
        
        print("\n" + "=" * 70)
        print("✅ Model training completed successfully!")
        print(f"🎯 Best Model: {self.best_model_name}")
        print(f"📊 Best Accuracy: {self.results[self.best_model_name]['accuracy']:.4f}")
        print("💾 Models saved for web deployment")
        print("=" * 70)

# Main execution
if __name__ == "__main__":
    # Update the file path to your dataset
    DATA_FILE_PATH = "phishing_dataset.csv"  # Change this to your actual file path
    
    # Create trainer instance and run pipeline
    trainer = PhishingModelTrainer(DATA_FILE_PATH)
    trainer.run_complete_training()