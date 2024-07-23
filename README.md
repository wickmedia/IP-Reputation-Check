# IP-Reputation-Check
Check IP Reputation in Bulk
----------------------------------------------
Prerequisites:

Python installed on your system.
Required Python packages: pandas, requests, openpyxl.
An API token.
Input Excel file containing the IOCs.

Setup:

Ensure your API token is saved in a text file at the specified path (e.g., "Path\api_token.txt").
Prepare an input Excel file with a column named 'IOC' containing the list of IP addresses(e.g., "Path\File_Name.xlsx").
Configuration:

Adjust the paths for API_TOKEN_FILE, INPUT_FILENAME, and OUTPUT_EXCEL_FILENAME to match your environment and file locations.
Ensure the BATCH_SIZE and DELAY_SECONDS are set according to your requirements.

Running the Script:

Execute the script in your Python environment. The script will:
    Read the API token from the specified file.
    Read the input Excel file and extract IOCs.
    Process the IOCs in batches of 2000, sending them to the API and waiting for responses.
    Append the responses to an output Excel file.
    Track the progress of the processing.
    Save the final output to the specified Excel file once all IOCs have been processed.

Keeping Data
Input Data: The input Excel file (Input.xlsx) should have a column named 'IOC' which contains the list of IP's to be processed.

Output Data: The output Excel file (Output.xlsx) will contain the API responses.

Progress Tracking: The script tracks and prints the progress of each batch processed, including the number of IOCs processed so far.

Error Handling: The script handles missing keys in the API response and ensures that it only appends valid data to the output file.

Notes
Ensure that the API token and file paths are correct and accessible.
The script introduces a delay of 10 seconds between batches to comply with API rate limits.
If the script encounters an error, it will print the error message and continue processing the next batch.
This script ensures efficient and automated processing of large sets of IOCs, making it suitable for cybersecurity and threat intelligence tasks.
