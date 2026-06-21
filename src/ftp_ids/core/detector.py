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
        self.features_cols = FEATURE_NAMES
        self.scaler = StandardScaler()
        self.pipeline = None
        self.score_scaler = None
    
    def load_model(self):
        if os.path.exists(self.model_path):
            saved_state = joblib.load(self.model_path)
            self.pipeline = saved_state.get('pipeline') 
            self.score_scaler = saved_state.get('score_scaler') 
            return True
        return False
    
    def train(self, sessions):
        features = self.extractor.extract_batch(sessions)
        df = pd.DataFrame(features)
        X = df[self.features_cols]        

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
        
        raw_scores = self.pipeline.decision_function(X)
        self.score_scaler = MinMaxScaler(feature_range=(0, 1))
        self.score_scaler.fit(raw_scores.reshape(-1, 1))
    
        joblib.dump({
            "pipeline": self.pipeline,
            "score_scaler": self.score_scaler
        }, self.model_path)

        print(f"Model trained and saved to {self.model_path}")

    

    # def _vectorize(self, sessions):
    #     features = self.extractor.extract_batch(sessions)
        
        