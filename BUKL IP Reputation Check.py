import os
import pandas as pd
import requests
import json
import time

# Define file paths
API_TOKEN_FILE = r'Path_to\api_token.txt'
INPUT_FILENAME = r'Path_to\Input.xlsx'
OUTPUT_EXCEL_FILENAME = r'Path_to\output.xlsx'
BATCH_SIZE = 2000
DELAY_SECONDS = 10

# API endpoint URL
FUSION_POST_URL = 'Endpoint URL Here'

# Function to read the API token from the file
def get_api_token():
    if not os.path.exists(API_TOKEN_FILE):
        token = input("Enter your API token: ")
        with open(API_TOKEN_FILE, 'w') as file:
            file.write(token)
        return token
    else:
        with open(API_TOKEN_FILE, 'r') as file:
            return file.read().strip()

# Initialize API_TOKEN
API_TOKEN = get_api_token()

# Function to check if all IOCs have received responses
def all_responses_received(df_iocs, df_output):
    iocs_with_response = df_output['IP Address'].tolist()
    all_iocs = df_iocs['IOC'].tolist()
    return all(ioc in iocs_with_response for ioc in all_iocs)

# Function to post a batch of IOCs and return the response
def post_iocs(iocs_batch):
    try:
        payload = {"ip": iocs_batch}  # Format the batch as {"ip": [list of IPs]}
        
        response = requests.post(FUSION_POST_URL,
                                 headers={'X-RFToken': API_TOKEN},
                                 json=payload)
        response.raise_for_status()
        
        return response.json()  # Return JSON response
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None

# Function to track progress
def track_progress(current_batch, total_batches, iocs_processed):
    print(f"Processed batch {current_batch} of {total_batches}. {iocs_processed} IOCs processed.")

# Read the input Excel file
df_iocs = pd.read_excel(INPUT_FILENAME)

# Assuming the IOC column is named 'IOC', change if necessary
ioc_column_name = 'IOC'  # Change this if the column name is different
if ioc_column_name not in df_iocs.columns:
    raise KeyError(f"Column '{ioc_column_name}' not found in the Excel file.")

iocs = df_iocs[ioc_column_name].tolist()

# Initialize DataFrame for output
if os.path.exists(OUTPUT_EXCEL_FILENAME):
    df_output = pd.read_excel(OUTPUT_EXCEL_FILENAME)
else:
    df_output = pd.DataFrame(columns=['IP Address', 'Risk Score', 'Risk Level', 'Phishing Score', 'Phishing Count',
                                      'Public Score', 'Public Most Critical Rule', 'C2 Score', 'C2 Count',
                                      'Historical Threat List', 'Historical Threat Count', 'Historical Threat Timestamp',
                                      'Unusual IP', 'Unusual IP Count', 'Unusual IP Timestamp',
                                      'Brute Force', 'Brute Force Count', 'Brute Force Timestamp'])

# Process IOCs in batches and collect responses
for i in range(0, len(iocs), BATCH_SIZE):
    batch = iocs[i:i + BATCH_SIZE]
    
    # Check if batch has already been processed
    batch_to_process = [ioc for ioc in batch if ioc not in df_output['IP Address'].tolist()]
    
    if not batch_to_process:
        track_progress(i // BATCH_SIZE + 1, len(iocs) // BATCH_SIZE, len(df_output))
        continue
    
    # Send batch request
    response = post_iocs(batch_to_process)
    
    if response:
        # Append responses to DataFrame
        flattened_responses = []
        for result in response.get('data', {}).get('results', []):
            response_data = {
                'IP Address': result['entity']['name'],
                'Risk Score': result['risk']['score'],
                'Risk Level': result['risk']['level'],
                'Phishing Score': result['risk']['context']['phishing'].get('score', None),
                'Phishing Count': result['risk']['context']['phishing']['rule'].get('count', None),
                'Public Score': result['risk']['context']['public'].get('score', None),
                'Public Most Critical Rule': result['risk']['context']['public'].get('mostCriticalRule', None),
                'C2 Score': result['risk']['context']['c2'].get('score', None),
                'C2 Count': result['risk']['context']['c2']['rule'].get('count', None),
                'Historical Threat List': result['risk']['rule'].get('summary', []),
                'Historical Threat Count': result['risk']['rule'].get('count', None),
                'Historical Threat Timestamp': result['risk']['rule'].get('timestamp', None),
                'Unusual IP': result['risk']['context'].get('unusual', {}).get('summary', []),
                'Unusual IP Count': result['risk']['context'].get('unusual', {}).get('count', None),
                'Unusual IP Timestamp': result['risk']['context'].get('unusual', {}).get('timestamp', None),
                'Brute Force': result['risk']['context'].get('bruteForce', {}).get('summary', []),
                'Brute Force Count': result['risk']['context'].get('bruteForce', {}).get('count', None),
                'Brute Force Timestamp': result['risk']['context'].get('bruteForce', {}).get('timestamp', None)
            }
            flattened_responses.append(response_data)
        
        df_batch_output = pd.DataFrame(flattened_responses)
        
        # Append batch responses to output DataFrame
        df_output = pd.concat([df_output, df_batch_output], ignore_index=True)
        
        # Track progress
        track_progress(i // BATCH_SIZE + 1, len(iocs) // BATCH_SIZE, len(df_output))
        
        # Introduce delay between batches
        time.sleep(DELAY_SECONDS)
    else:
        print(f"Error processing batch {i+1}-{i+len(batch)}")

# Save DataFrame to Excel
df_output.to_excel(OUTPUT_EXCEL_FILENAME, index=False)

print(f"All API responses have been appended and saved to {OUTPUT_EXCEL_FILENAME}")
