import pandas as pd

def extract_features(df):
    """
    Extracts numerical features from the parsed log DataFrame.
    Groups data by IP address to find anomalous behavior per IP.
    """
    # Filter out logs where we couldn't find an IP
    df = df[df['ip_address'] != 'Unknown']
    
    # Create dummy variables for event types
    event_dummies = pd.get_dummies(df['event_type'])
    df_events = pd.concat([df['ip_address'], event_dummies], axis=1)
    
    # Aggregate by IP address
    features = df_events.groupby('ip_address').sum()
    
    # Ensure our expected columns exist even if they didn't appear in the logs
    expected_cols = ['failed_login', 'successful_login', 'invalid_user', 'connection_closed', 'other']
    for col in expected_cols:
        if col not in features.columns:
            features[col] = 0
            
    # Engineer derivative features
    features['total_activity'] = features.sum(axis=1)
    
    # Prevent division by zero
    features['failure_ratio'] = features['failed_login'] / features['total_activity'].replace(0, 1)
    features['invalid_user_ratio'] = features['invalid_user'] / features['total_activity'].replace(0, 1)
    
    # Drop rows with 0 activity just in case
    features = features[features['total_activity'] > 0]
    
    return features