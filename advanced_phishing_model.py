import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
import tldextract
import socket
import ssl
import whois
from datetime import datetime
import pickle
import joblib
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.metrics import roc_curve, auc, classification_report
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from xgboost import XGBClassifier
import warnings
warnings.filterwarnings('ignore')

class AdvancedPhishingDetector:
    def __init__(self):
        self.models = {}
        self.fusion_model = None
        self.scaler = StandardScaler()
        self.feature_selector = None
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        self.is_trained = False
        
    def extract_advanced_features(self, url):
        """Extract comprehensive features from URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            features = {}
            
            # Basic URL features
            features['url_length'] = len(url)
            features['domain_length'] = len(extracted.domain)
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query)
            features['fragment_length'] = len(parsed.fragment)
            
            # Protocol features
            features['has_https'] = 1 if parsed.scheme == 'https' else 0
            features['has_www'] = 1 if extracted.subdomain == 'www' else 0
            
            # Domain features
            features['num_dots'] = url.count('.')
            features['num_dashes'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_slashes'] = url.count('/')
            features['num_question_marks'] = url.count('?')
            features['num_equal_signs'] = url.count('=')
            features['num_at_symbols'] = url.count('@')
            features['num_tildes'] = url.count('~')
            features['num_percentages'] = url.count('%')
            features['num_hashes'] = url.count('#')
            features['num_ampersands'] = url.count('&')
            features['num_spaces'] = url.count(' ')
            features['num_tabs'] = url.count('\t')
            features['num_returns'] = url.count('\r')
            features['num_newlines'] = url.count('\n')
            
            # Character features
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['num_letters'] = sum(c.isalpha() for c in url)
            features['num_lowercase'] = sum(c.islower() for c in url)
            features['num_uppercase'] = sum(c.isupper() for c in url)
            features['num_special_chars'] = sum(not c.isalnum() and not c.isspace() for c in url)
            
            # Domain-specific features
            features['domain_with_digits'] = 1 if any(c.isdigit() for c in extracted.domain) else 0
            features['domain_with_dashes'] = 1 if '-' in extracted.domain else 0
            features['domain_with_underscores'] = 1 if '_' in extracted.domain else 0
            features['domain_starts_with_digit'] = 1 if extracted.domain and extracted.domain[0].isdigit() else 0
            features['domain_ends_with_digit'] = 1 if extracted.domain and extracted.domain[-1].isdigit() else 0
            
            # Subdomain features
            features['num_subdomains'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['subdomain_length'] = len(extracted.subdomain) if extracted.subdomain else 0
            
            # TLD features
            features['tld_length'] = len(extracted.suffix)
            features['tld_with_digits'] = 1 if any(c.isdigit() for c in extracted.suffix) else 0
            
            # Suspicious patterns
            features['has_ip'] = 1 if bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url)) else 0
            features['has_hex'] = 1 if bool(re.search(r'0x[0-9a-fA-F]+', url)) else 0
            features['has_binary'] = 1 if bool(re.search(r'[01]{8,}', url)) else 0
            
            # URL shortening services
            shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.gs', 
                                'ow.ly', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'u.to', 'tiny.cc']
            features['uses_shortening_service'] = 1 if any(service in url.lower() for service in shortening_services) else 0
            
            # Suspicious TLDs
            suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'ru', 'info', 'click', 'link', 'bid', 'party', 'webcam', 'win']
            features['has_suspicious_tld'] = 1 if extracted.suffix in suspicious_tlds else 0
            
            # Brand detection (simplified)
            common_brands = ['google', 'facebook', 'amazon', 'paypal', 'microsoft', 'netflix', 'instagram', 'twitter', 'apple', 'yahoo']
            features['contains_brand_terms'] = 1 if any(brand in url.lower() for brand in common_brands) else 0
            
            # Typosquatting detection
            features['is_typosquatting'] = self._detect_typosquatting(url, common_brands)
            
            # Skip slow SSL and domain age checks for training
            features['has_valid_ssl'] = 0 
            features['domain_age'] = -1  

            features['avg_word_length'] = np.mean([len(word) for word in url.split('/') if word]) if url.split('/') else 0
            features['entropy'] = self._calculate_entropy(url)
            features['special_char_ratio'] = features['num_special_chars'] / max(features['url_length'], 1)
            features['digit_ratio'] = features['num_digits'] / max(features['url_length'], 1)
            features['letter_ratio'] = features['num_letters'] / max(features['url_length'], 1)
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            return self._get_default_features()
    
    def _detect_typosquatting(self, url, brands):
        """Detect typosquatting patterns"""
        domain = tldextract.extract(url).domain.lower()
        
        for brand in brands:
            if brand in domain and brand != domain:
                if self._levenshtein_distance(brand, domain) <= 2:
                    return 1
        return 0
    
    def _levenshtein_distance(self, s1, s2):
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _check_ssl_certificate(self, url):
        """Check if URL has valid SSL certificate"""
        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return 1 if cert and 'notAfter' in cert else 0
        except:
            return 0
    
    def _get_domain_age(self, domain):
        """Get domain age in days"""
        try:
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                    
                domain_age = (datetime.now() - creation_date).days
                return max(0, domain_age)
            return -1
        except:
            return -1
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        # Count character frequencies
        freq = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(string)
        for count in freq.values():
            p = count / length
            entropy -= p * np.log2(p)
        
        return entropy
    
    def _get_default_features(self):
        """Return default features when extraction fails"""
        return {
            'url_length': 0, 'domain_length': 0, 'path_length': 0, 'query_length': 0,
            'fragment_length': 0, 'has_https': 0, 'has_www': 0, 'num_dots': 0,
            'num_dashes': 0, 'num_underscores': 0, 'num_slashes': 0, 'num_question_marks': 0,
            'num_equal_signs': 0, 'num_at_symbols': 0, 'num_tildes': 0, 'num_percentages': 0,
            'num_hashes': 0, 'num_ampersands': 0, 'num_spaces': 0, 'num_tabs': 0,
            'num_returns': 0, 'num_newlines': 0, 'num_digits': 0, 'num_letters': 0,
            'num_lowercase': 0, 'num_uppercase': 0, 'num_special_chars': 0,
            'domain_with_digits': 0, 'domain_with_dashes': 0, 'domain_with_underscores': 0,
            'domain_starts_with_digit': 0, 'domain_ends_with_digit': 0, 'num_subdomains': 0,
            'subdomain_length': 0, 'tld_length': 0, 'tld_with_digits': 0, 'has_ip': 0,
            'has_hex': 0, 'has_binary': 0, 'uses_shortening_service': 0, 'has_suspicious_tld': 0,
            'contains_brand_terms': 0, 'is_typosquatting': 0, 'has_valid_ssl': 0,
            'domain_age': -1, 'avg_word_length': 0, 'entropy': 0, 'special_char_ratio': 0,
            'digit_ratio': 0, 'letter_ratio': 0
        }
    
    def prepare_data(self, df):
        """Prepare data for training"""
        print("Extracting features from URLs...")

        features_list = []
        sample_size = min(10000, len(df)) 
        df_sample = df.sample(n=sample_size, random_state=42)
        
        for i, (_, row) in enumerate(df_sample.iterrows()):
            if i % 1000 == 0:
                print(f"Processing URL {i+1}/{sample_size}")
            features = self.extract_advanced_features(row['url'])
            features_list.append(features)
        
        features_df = pd.DataFrame(features_list)

        if 'label' in df_sample.columns:
            y = df_sample['label']
        elif 'Label' in df_sample.columns:
            y = df_sample['Label']
        else:
            raise ValueError("No label column found in dataset")

        if y.dtype == 'object':
            y = self.label_encoder.fit_transform(y)

        self.feature_names = features_df.columns.tolist()
        
        return features_df, y
    
    def train_fusion_model(self, df, test_size=0.2, random_state=42):
        """Train the fusion model with multiple algorithms"""
        print("Preparing data...")
        X, y = self.prepare_data(df)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        print("Performing feature selection...")
        self.feature_selector = SelectKBest(f_classif, k=min(20, X.shape[1]))
        X_train_selected = self.feature_selector.fit_transform(X_train, y_train)
        X_test_selected = self.feature_selector.transform(X_test)

        selected_indices = self.feature_selector.get_support(indices=True)
        self.selected_feature_names = [self.feature_names[i] for i in selected_indices]

        print("Scaling features...")
        X_train_scaled = self.scaler.fit_transform(X_train_selected)
        X_test_scaled = self.scaler.transform(X_test_selected)
        
        # Train individual models
        print("Training individual models...")
        self.models = {
            'XGBoost': XGBClassifier(
                n_estimators=100, 
                learning_rate=0.1, 
                max_depth=6,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=random_state,
                eval_metric='logloss'
            ),
            'RandomForest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=random_state
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                subsample=0.8,
                random_state=random_state
            ),
            'LogisticRegression': LogisticRegression(
                max_iter=1000,
                C=1.0,
                random_state=random_state
            )
        }
        
        # Train each model
        model_scores = {}
        for name, model in self.models.items():
            print(f"Training {name}...")
            model.fit(X_train_scaled, y_train)
            y_pred = model.predict(X_test_scaled)
            score = f1_score(y_test, y_pred)
            model_scores[name] = score
            print(f"{name} F1 Score: {score:.4f}")
        
        # Create fusion models
        print("Creating fusion models...")
        
        # 1. Voting Classifier (Soft)
        estimators = [(name, model) for name, model in self.models.items()]
        voting_classifier = VotingClassifier(
            estimators=estimators,
            voting='soft'
        )
        voting_classifier.fit(X_train_scaled, y_train)
        
        # 2. Weighted Ensemble
        weights = np.array([model_scores[name] for name in self.models.keys()])
        weights = weights / np.sum(weights)  
        
        class WeightedEnsemble:
            def __init__(self, models, weights):
                self.models = models
                self.weights = weights
            
            def predict(self, X):
                predictions = np.zeros((X.shape[0], 2))
                for model, weight in zip(self.models.values(), self.weights):
                    pred_proba = model.predict_proba(X)
                    predictions += weight * pred_proba
                return (predictions[:, 1] >= 0.5).astype(int)
            
            def predict_proba(self, X):
                predictions = np.zeros((X.shape[0], 2))
                for model, weight in zip(self.models.values(), self.weights):
                    pred_proba = model.predict_proba(X)
                    predictions += weight * pred_proba
                return predictions
        
        weighted_ensemble = WeightedEnsemble(self.models, weights)
        
        # Evaluate fusion models
        fusion_models = {
            'Voting': voting_classifier,
            'WeightedEnsemble': weighted_ensemble
        }
        
        print("\nFusion Model Evaluation:")
        print("-" * 40)
        
        best_score = 0
        best_model_name = None
        
        for name, model in fusion_models.items():
            if hasattr(model, 'predict'):
                y_pred = model.predict(X_test_scaled)
                score = f1_score(y_test, y_pred)
                print(f"{name} F1 Score: {score:.4f}")
                
                if score > best_score:
                    best_score = score
                    best_model_name = name
                    self.fusion_model = model
        
        print(f"\nBest fusion model: {best_model_name} (F1 Score: {best_score:.4f})")
        
        # Final evaluation
        y_pred_final = self.fusion_model.predict(X_test_scaled)
        y_pred_proba = self.fusion_model.predict_proba(X_test_scaled)[:, 1] if hasattr(self.fusion_model, 'predict_proba') else None
        
        print("\nFinal Model Performance:")
        print(f"Accuracy: {accuracy_score(y_test, y_pred_final):.4f}")
        print(f"Precision: {precision_score(y_test, y_pred_final):.4f}")
        print(f"Recall: {recall_score(y_test, y_pred_final):.4f}")
        print(f"F1 Score: {f1_score(y_test, y_pred_final):.4f}")
        
        if y_pred_proba is not None:
            fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
            roc_auc = auc(fpr, tpr)
            print(f"ROC AUC: {roc_auc:.4f}")
        
        self.is_trained = True
        return X_test_scaled, y_test, y_pred_final
    
    def predict(self, url):
        """Predict phishing probability for a single URL"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")

        features = self.extract_advanced_features(url)
        features_df = pd.DataFrame([features])

        X_selected = self.feature_selector.transform(features_df)

        X_scaled = self.scaler.transform(X_selected)

        if hasattr(self.fusion_model, 'predict_proba'):
            probability = self.fusion_model.predict_proba(X_scaled)[0, 1]
        else:
            probability = self.fusion_model.predict(X_scaled)[0]
        
        prediction = 1 if probability >= 0.5 else 0
        
        return {
            'prediction': prediction,
            'probability': probability,
            'features': features
        }
    
    def save_model(self, filepath):
        """Save the trained model"""
        model_data = {
            'models': self.models,
            'fusion_model': self.fusion_model,
            'scaler': self.scaler,
            'feature_selector': self.feature_selector,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'selected_feature_names': self.selected_feature_names,
            'is_trained': self.is_trained
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load a trained model"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.models = model_data['models']
        self.fusion_model = model_data['fusion_model']
        self.scaler = model_data['scaler']
        self.feature_selector = model_data['feature_selector']
        self.label_encoder = model_data['label_encoder']
        self.feature_names = model_data['feature_names']
        self.selected_feature_names = model_data['selected_feature_names']
        self.is_trained = model_data['is_trained']
        
        print(f"Model loaded from {filepath}")

def main():
    """Main function to train the model"""
    print("Advanced Phishing Detection Model Training")
    print("=" * 50)

    try:
        df = pd.read_csv('phishing_dataset.csv')
        print(f"Dataset loaded: {df.shape}")
    except FileNotFoundError:
        print("Error: phishing_dataset.csv not found")
        return

    detector = AdvancedPhishingDetector()

    X_test, y_test, y_pred = detector.train_fusion_model(df)

    detector.save_model('advanced_phishing_model.pkl')
    
    print("\nTraining completed successfully!")
    print("Model saved as 'advanced_phishing_model.pkl'")

if __name__ == "__main__":
    main() 