"""
Machine learning based anomaly detection.
"""

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional
import joblib
import logging

logger = logging.getLogger(__name__)

class MLDetector:
    """Machine learning based network traffic analyzer."""
    
    def __init__(self, model_path: Optional[str] = None):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.trained = False
        
        if model_path:
            self.load_model(model_path)
    
    def extract_features(self, flow_data: Dict) -> np.ndarray:
        """Extract features from flow data."""
        features = [
            flow_data.get('bytes_in', 0),
            flow_data.get('bytes_out', 0),
            flow_data.get('packets_in', 0),
            flow_data.get('packets_out', 0),
            flow_data.get('duration', 0),
            flow_data.get('avg_packet_size', 0),
            flow_data.get('protocol', 0),
            flow_data.get('port', 0)
        ]
        return np.array(features).reshape(1, -1)
    
    def train(self, normal_flows: List[Dict]) -> None:
        """Train the detector on normal traffic."""
        if not normal_flows:
            raise ValueError("No training data provided")
            
        # Extract features
        features = np.vstack([
            self.extract_features(flow)[0] for flow in normal_flows
        ])
        
        # Fit scaler
        self.scaler.fit(features)
        scaled_features = self.scaler.transform(features)
        
        # Train isolation forest
        self.isolation_forest.fit(scaled_features)
        
        # Generate synthetic anomalies for classifier
        normal_labels = np.zeros(len(normal_flows))
        synthetic_anomalies = np.random.uniform(
            low=scaled_features.min(axis=0) - 1,
            high=scaled_features.max(axis=0) + 1,
            size=(len(normal_flows) // 10, scaled_features.shape[1])
        )
        anomaly_labels = np.ones(len(synthetic_anomalies))
        
        # Train classifier
        X = np.vstack([scaled_features, synthetic_anomalies])
        y = np.hstack([normal_labels, anomaly_labels])
        self.classifier.fit(X, y)
        
        self.trained = True
        logger.info("ML detector training completed")
    
    def detect(self, flow: Dict) -> Tuple[bool, float, str]:
        """Detect if a flow is anomalous."""
        if not self.trained:
            raise RuntimeError("Detector not trained")
            
        features = self.extract_features(flow)
        scaled_features = self.scaler.transform(features)
        
        # Get isolation forest score
        if_score = self.isolation_forest.score_samples(scaled_features)[0]
        
        # Get classifier probability
        clf_prob = self.classifier.predict_proba(scaled_features)[0][1]
        
        # Combine scores
        combined_score = (clf_prob + (0.5 - if_score/2)) / 2
        
        is_anomaly = combined_score > 0.8
        reason = self._get_anomaly_reason(flow, combined_score)
        
        return is_anomaly, combined_score, reason
    
    def _get_anomaly_reason(self, flow: Dict, score: float) -> str:
        """Generate reason for anomaly classification."""
        reasons = []
        
        if flow.get('bytes_out', 0) > 1000000:
            reasons.append("Large outbound transfer")
            
        if flow.get('duration', 0) < 1 and flow.get('packets_out', 0) > 100:
            reasons.append("Burst of packets")
            
        if score > 0.95:
            reasons.append("Highly anomalous behavior")
        elif score > 0.8:
            reasons.append("Moderately anomalous behavior")
            
        return ", ".join(reasons) if reasons else "Unknown anomaly pattern"
    
    def save_model(self, path: str) -> None:
        """Save the trained model."""
        if not self.trained:
            raise RuntimeError("Cannot save untrained model")
            
        model_data = {
            'scaler': self.scaler,
            'isolation_forest': self.isolation_forest,
            'classifier': self.classifier,
            'trained': self.trained
        }
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")
    
    def load_model(self, path: str) -> None:
        """Load a trained model."""
        try:
            model_data = joblib.load(path)
            self.scaler = model_data['scaler']
            self.isolation_forest = model_data['isolation_forest']
            self.classifier = model_data['classifier']
            self.trained = model_data['trained']
            logger.info(f"Model loaded from {path}")
        except Exception as e:
            logger.error(f"Error loading model from {path}: {e}")
            raise
