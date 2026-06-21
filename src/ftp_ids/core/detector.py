import os
import joblib
from ftp_ids.core.feature_extractor import FeatureExtractor, FEATURE_NAMES
from pprint import pprint
import pandas as pd
from sklearn.ensemble import IsolationForest

class Detector:

    def __init__(self, model_path, contamination ):
        self.model_path = model_path
        self.contamination = contamination
        self.model = None
        self.extractor = FeatureExtractor()
        self.features_cols = FEATURE_NAMES

    
    def load_modal(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model)
            return True
        return False
    
    def train(self, sessions):
        # self._vectorize(sessions)
        features = self.extractor.extract_batch(sessions)

        # pprint(features)

        df = pd.DataFrame(features)

        X = df[self.features_cols]

        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42
        )

        self.model.fit(X)

        joblib.dump(self.model, self.model_path)
        print(f"Model trained and saved to {self.model_path}")

   