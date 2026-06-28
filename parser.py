import re
import pandas as pd

def parse_auth_log(file_path):
    """Parses an auth.log file and returns a pandas DataFrame."""
    
    # Standard syslog regex: Month Day Time Hostname Process[PID]: Message
    log_pattern = re.compile(
        r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+(?P<process>[a-zA-Z0-9_\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
    )
    
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    
    parsed_data = []
    
    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                log_dict = match.groupdict()
                message = log_dict['message']
                
                # Only process sshd logs for this specific use case
                if 'sshd' not in log_dict['process']:
                    continue
                
                # Extract IP if present
                ip_match = ip_pattern.search(message)
                log_dict['ip_address'] = ip_match.group(1) if ip_match else 'Unknown'
                
                # Categorize the event type
                if 'Failed password' in message:
                    log_dict['event_type'] = 'failed_login'
                elif 'Accepted password' in message or 'Accepted publickey' in message:
                    log_dict['event_type'] = 'successful_login'
                elif 'Invalid user' in message:
                    log_dict['event_type'] = 'invalid_user'
                elif 'Connection closed' in message:
                    log_dict['event_type'] = 'connection_closed'
                else:
                    log_dict['event_type'] = 'other'
                
                parsed_data.append(log_dict)
                
    df = pd.DataFrame(parsed_data)
    return df