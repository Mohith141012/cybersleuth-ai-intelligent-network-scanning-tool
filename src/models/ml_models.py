import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import logging

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def train(self, data):
        """Train the anomaly detection model"""
        try:
            scaled_data = self.scaler.fit_transform(data)
            self.model.fit(scaled_data)
            self.is_trained = True
        except Exception as e:
            logger.error(f"Error training anomaly detector: {str(e)}")

    def detect(self, data):
        """Detect anomalies in the data"""
        try:
            if not self.is_trained:
                logger.warning("Model not trained yet. Using default parameters.")
                self.train(np.array(data).reshape(-1, 1))
            
            scaled_data = self.scaler.transform(np.array(data).reshape(-1, 1))
            predictions = self.model.predict(scaled_data)
            return bool(np.any(predictions == -1))
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            return False

class LogAnomalyDetector:
    def __init__(self):
        self.model = nn.Sequential(
            nn.Linear(10, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 2)
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def _prepare_features(self, log_data):
        """Extract features from log data"""
        features = np.zeros((len(log_data), 10))
        for i, entry in enumerate(log_data):
            features[i] = [
                entry.get('event_frequency', 0),
                entry.get('time_of_day', 0),
                entry.get('severity_level', 0),
                entry.get('source_ip_count', 0),
                entry.get('destination_ip_count', 0),
                entry.get('unique_users', 0),
                entry.get('error_count', 0),
                entry.get('warning_count', 0),
                entry.get('critical_count', 0),
                entry.get('authentication_failures', 0)
            ]
        return features

    def train(self, log_data, labels):
        """Train the log anomaly detection model"""
        try:
            features = self._prepare_features(log_data)
            scaled_features = self.scaler.fit_transform(features)
            X = torch.FloatTensor(scaled_features)
            y = torch.LongTensor(labels)
            
            criterion = nn.CrossEntropyLoss()
            optimizer = torch.optim.Adam(self.model.parameters())
            
            for epoch in range(100):
                optimizer.zero_grad()
                outputs = self.model(X)
                loss = criterion(outputs, y)
                loss.backward()
                optimizer.step()
            
            self.is_trained = True
        except Exception as e:
            logger.error(f"Error training log anomaly detector: {str(e)}")

    def detect(self, log_data):
        """Detect anomalies in log data"""
        try:
            features = self._prepare_features([log_data])
            scaled_features = self.scaler.transform(features)
            X = torch.FloatTensor(scaled_features)
            
            with torch.no_grad():
                outputs = F.softmax(self.model(X), dim=1)
            return outputs[0][1].item() > 0.5
        except Exception as e:
            logger.error(f"Error detecting log anomalies: {str(e)}")
            return False

class ImageAnalyzer:
    def __init__(self):
        self.model = nn.Sequential(
            nn.Linear(5, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 2)
        )
        self.scaler = StandardScaler()

    def preprocess_image(self, image):
        """Preprocess image for analysis"""
        try:
            if len(image.shape) == 3:
                image = np.mean(image, axis=2)
            flattened = image.flatten()
            return flattened
        except Exception as e:
            logger.error(f"Error preprocessing image: {str(e)}")
            return None

    def analyze(self, image):
        """Analyze image for suspicious content"""
        try:
            processed_image = self.preprocess_image(image)
            if processed_image is None:
                return {'suspicious': False, 'confidence': 0}

            features = self._extract_image_features(processed_image)
            X = torch.FloatTensor([list(features.values())])
            
            with torch.no_grad():
                outputs = F.softmax(self.model(X), dim=1)
            prediction = outputs[0][1].item()

            return {
                'suspicious': bool(prediction > 0.5),
                'confidence': float(prediction),
                'features_detected': features
            }
        except Exception as e:
            logger.error(f"Error analyzing image: {str(e)}")
            return {'suspicious': False, 'confidence': 0}

    def _extract_image_features(self, image):
        """Extract relevant features from image"""
        try:
            return {
                'mean': np.mean(image),
                'std': np.std(image),
                'min': np.min(image),
                'max': np.max(image),
                'median': np.median(image)
            }
        except Exception as e:
            logger.error(f"Error extracting image features: {str(e)}")
            return {}

class TextAnalyzer:
    def __init__(self):
        self.model = nn.Sequential(
            nn.Linear(5, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 2)
        )

    def analyze(self, text):
        """Analyze text for suspicious content"""
        try:
            features = self._extract_text_features(text)
            X = torch.FloatTensor([list(features.values())])
            
            with torch.no_grad():
                outputs = F.softmax(self.model(X), dim=1)
            prediction = outputs[0][1].item()
            
            return {
                'suspicious': bool(prediction > 0.5),
                'confidence': float(prediction),
                'features': features
            }
        except Exception as e:
            logger.error(f"Error analyzing text: {str(e)}")
            return {'suspicious': False, 'confidence': 0}

    def _preprocess_text(self, text):
        """Preprocess text for analysis"""
        try:
            return text.lower()
        except Exception as e:
            logger.error(f"Error preprocessing text: {str(e)}")
            return ""

    def _extract_text_features(self, text):
        """Extract relevant features from text"""
        try:
            preprocessed_text = self._preprocess_text(text)
            return {
                'length': len(preprocessed_text),
                'word_count': len(preprocessed_text.split()),
                'unique_words': len(set(preprocessed_text.split())),
                'special_chars': sum(not c.isalnum() for c in preprocessed_text),
                'numeric_count': sum(c.isdigit() for c in preprocessed_text)
            }
        except Exception as e:
            logger.error(f"Error extracting text features: {str(e)}")
            return {} 