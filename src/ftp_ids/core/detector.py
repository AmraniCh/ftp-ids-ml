import os
import joblib
from ftp_ids.core.feature_extractor import FeatureExtractor, FEATURE_NAMES
from pprint import pprint
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline

class Detector:

    def __init__(self, model_path, contamination ):
        self.model_path = model_path
        self.contamination = contamination
        self.extractor = FeatureExtractor()
        self.feature_names = FEATURE_NAMES
        self.scaler = StandardScaler()
        self.pipeline = None
        self.score_scaler = None
    
    def load_model(self):
        if os.path.exists(self.model_path):
            saved_state = joblib.load(self.model_path)
            self.pipeline = saved_state.get('pipeline') 
            self.scaler = saved_state.get('scaler')
            self.score_scaler = saved_state.get('score_scaler')
            self.feature_names = saved_state.get('features') 
            return True
        return False
    
    def train(self, sessions):
        features = self.extractor.extract_batch(sessions)
        df = pd.DataFrame(features)
        X = df[self.feature_names]      

        # TODO consider to test with dynamic contamination based on session events length
        self.pipeline = Pipeline([
            ('scaler', self.scaler), 
            ('iso_forest', IsolationForest(
                n_estimators=200,
                contamination=self.contamination,
                random_state=42
            ))
        ])

        self.pipeline.fit(X)
        
        raw_scores = -self.pipeline.decision_function(X)
        self.score_scaler = MinMaxScaler(feature_range=(0, 1))
        self.score_scaler.fit(raw_scores.reshape(-1, 1))
    
        joblib.dump({
            "pipeline": self.pipeline,
            "scaler": self.scaler,
            "score_scaler": self.score_scaler,
            "features": self.feature_names
        }, self.model_path)

        print(f"Model trained and saved to {self.model_path}")

    
    def score(self, session):

        if self.pipeline is None and not self.load_model():
            raise RuntimeError("train the model first!")
        
        features = self.extractor.extract(session)
        df = pd.DataFrame([features])
        X = df[self.feature_names]

        raw = -self.pipeline.decision_function(X)[0]
        normalized = self.score_scaler.transform([[raw]])[0][0]

        return float(normalized)
    
    def score_batch(self, sessions):
        return [self.score(session) for session in sessions]

    def train_on_features(self, X: pd.DataFrame):
        X = X[self.feature_names]

        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("iso_forest", IsolationForest(
                n_estimators=200,
                contamination=self.contamination,
                random_state=42,
            )),
        ])

        self.pipeline.fit(X)

        raw_scores = -self.pipeline.decision_function(X)
        self.score_scaler = MinMaxScaler(feature_range=(0, 1))
        self.score_scaler.fit(raw_scores.reshape(-1, 1))

        joblib.dump({
            "pipeline": self.pipeline,
            "scaler": self.scaler,
            "score_scaler": self.score_scaler,
            "features": self.feature_names,
        }, self.model_path)
        
        print(f"Model retrained and saved to {self.model_path}")