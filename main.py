import os
from parser import parse_auth_log
from features import extract_features
from model import SSHAnomalyDetector

def main():
    # Define the path to your auth.log file
    # You can point this to /var/log/auth.log if running on Linux, 
    # but it's safer to copy a sample locally first.
    log_file_path = 'OpenSSH_2k.log'  # Change this to your actual log file path
    
    if not os.path.exists(log_file_path):
        print(f"Error: Log file '{log_file_path}' not found.")
        print("Please place a sample SSH log named 'OpenSSH_2k.log' in the directory.")
        return

    print("1. Parsing SSH logs...")
    parsed_df = parse_auth_log(log_file_path)
    print(f"   Parsed {len(parsed_df)} SSH related log entries.")
    
    if parsed_df.empty:
        print("No SSH logs found to process.")
        return

    print("\n2. Extracting features per IP address...")
    features_df = extract_features(parsed_df)
    print(f"   Extracted features for {len(features_df)} unique IP addresses.")

    print("\n3. Training Isolation Forest and detecting anomalies...")
    # Adjust contamination based on how strict you want the detector to be (0.05 = 5% anomalies)
    detector = SSHAnomalyDetector(contamination=0.05)
    results_df = detector.fit_predict(features_df)

    print("\n4. Results:")
    anomalies = results_df[results_df['is_anomaly'] == True]
    
    if anomalies.empty:
        print("   No anomalies detected!")
    else:
        print(f"   Found {len(anomalies)} anomalous IP addresses:\n")
        
        # Sort by the anomaly score (lowest score = highest anomaly)
        anomalies_sorted = anomalies.sort_values(by='anomaly_score')
        
        # Print the IPs and their stats
        columns_to_show = ['failed_login', 'successful_login', 'invalid_user_ratio', 'anomaly_score']
        print(anomalies_sorted[columns_to_show])

if __name__ == "__main__":
    main()