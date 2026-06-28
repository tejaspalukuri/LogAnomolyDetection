from sklearn.ensemble import IsolationForest

class SSHAnomalyDetector:
    def __init__(self, contamination=0.05):
        """
        Initializes the Isolation Forest.
        contamination: The expected proportion of outliers in the data.
        """
        # random_state ensures reproducible results
        self.model = IsolationForest(
            n_estimators=100, 
            contamination='auto', 
            random_state=42
        )

    def fit_predict(self, features_df):
        """
        Trains the model and predicts anomalies.
        Returns the DataFrame with an added 'anomaly_score' and 'is_anomaly' column.
        """
        # We drop the string index (IP address) for training
        X = features_df.values
        
        # Fit the model and predict (-1 for anomalies, 1 for normal)
        predictions = self.model.fit_predict(X)
        
        # Get raw anomaly scores (lower is more anomalous)
        scores = self.model.decision_function(X)
        
        # Append results back to the dataframe
        results_df = features_df.copy()
        results_df['anomaly_score'] = scores
        results_df['is_anomaly'] = predictions
        
        # Convert -1/1 to True/False for easier reading
        results_df['is_anomaly'] = results_df['is_anomaly'].map({-1: True, 1: False})
        
        return results_df