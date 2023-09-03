"""
A script that conducts a security scan on a directory, and identifies presence of mentions, URLs, and potential API keys.
The output of the scan is written in a text file and console with a security score calculated based on pre-defined weights.

Note: The directory to scan and other parameters (such as company name) should be modified as per the user's requirements.

Author: Andy Tillo
License: MIT
"""

import os
import re
import time
from datetime import datetime
from tqdm import tqdm

def add_to_file_walkthrough(is_file_clean, file_path, file_walkthrough):
    """
    Adds a clean, dirty or skipped mark to the file_walkthrough. 

    Args:
        is_file_clean: A boolean indicating whether the file is secure
        file_path: The file's path
        file_walkthrough: List of file statuses

    Returns:
        Updated file walkthrough list
    """
    file_status = "[CLEAN!]" if is_file_clean else "[INVESTIGATE...]" 
    file_walkthrough.append(f"{file_status} {file_path}")

    return file_walkthrough
    

# Define constants
BASE_DIR = os.path.dirname(os.path.realpath(__file__))

datetime_str = datetime.now().strftime('%Y_%m_%d_%H%M%S%f')[:19]
OUT_FILENAME = os.path.join(BASE_DIR, f'{datetime_str}_pii_scan_results.txt')

TREE_TO_SCAN = "/Users/at/Desktop/code/boomi_golang"
SCRIPT_NAME = os.path.basename(__file__)
SKIP_DIRS = ['node_modules', '.git']
SKIP_FILES = ['.env', OUT_FILENAME, SCRIPT_NAME]
COMPANY_NAME = "company123"
YOUR_NAME = "Andy Tillo"
YOUR_EMAIL = "user@user.com"

# Weights for security scanner
COMPANY_NAME_IMPACT = 0.2
API_EXPOSURE_IMPACT = 10
YOUR_NAME_IMPACT = 0.0001
YOUR_EMAIL_IMPACT = 0.3
STARTING_SCORE = 100.0

# Significance scores for security scanner results
SIGNIFICANCE_SCORES = {
    'url': COMPANY_NAME_IMPACT,     
    'api_key': API_EXPOSURE_IMPACT,  
    'company_name': COMPANY_NAME_IMPACT,   
    'name_mention': YOUR_NAME_IMPACT,   
    'email_mention': YOUR_EMAIL_IMPACT   
}

# Regex patterns for URL, potential key, company name, your name and your email
REGEX_URL = r"https?://[^\s]+"
REGEX_POTENTIAL_KEY = r'(\bkey\b\s*[=:]\s*[A-Za-z0-9\-_~:/?#[\]@!$&()*+,;=`]{5,})'
REGEX_COMPANY_NAME = re.compile(COMPANY_NAME, re.I)
REGEX_YOUR_NAME = re.compile(YOUR_NAME, re.I)
REGEX_YOUR_EMAIL = re.compile(YOUR_EMAIL, re.I)

# Initialize counters
COUNTER_COMPANY_URL = 0
COUNTER_POTENTIAL_KEYS = []
COUNTER_COMPANY_NAME_FILES = []
COUNTER_YOUR_NAME_FILES = []
COUNTER_YOUR_EMAIL_FILES = []

print(f"Creating file: {OUT_FILENAME}")

# Initialize variables
total_scanned_files, total_skipped_files = 0, 0
file_walkthrough = []
start_time = time.time()

# Create a generator that will yield all the valid files
def files_to_scan():
    for root, dirs, files in os.walk(TREE_TO_SCAN):
        # Don't visit specified directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file in files:
            if file not in SKIP_FILES and not os.path.join(root, file) in SKIP_FILES:
                yield os.path.join(root, file)

# Create a pre-calculated list of files to get the total count for tqdm
list_of_files = list(files_to_scan())
total_files = len(list_of_files)

# Now start processing the files
for file_tobe_scanned in tqdm(list_of_files, total=total_files, desc="Scanning Files", bar_format="{l_bar}{bar} {n_fmt}/{total_fmt} Files | Elapsed Time: {elapsed} | Files per Second: {rate_fmt}{postfix}", leave=False):
    total_scanned_files += 1
    
    # Skip defined files
    if file_tobe_scanned in SKIP_FILES:
        total_skipped_files += 1
        file_walkthrough.append(f"[SKIPPED defined file] {file_tobe_scanned}")
        continue
    try:
        with open(file_tobe_scanned, 'r') as file_contents:
            data = file_contents.read().lower()
            is_file_clean = True  # Assume the file is clean initially.

            # Check for URLs with company name and potential api keys
            urls = re.findall(REGEX_URL, data, re.IGNORECASE)
            keys = re.findall(REGEX_POTENTIAL_KEY, data, re.IGNORECASE)

            # Add to company URL counter for each URL containing company name
            COUNTER_COMPANY_URL += sum([1 for url in urls if COMPANY_NAME in url])

            # Add to potential keys counter for each potential API key
            if keys:
                for key in keys:
                    key_value = key[1].split("=")[-1].strip() if '=' in key[1] else key[1].split(":")[-1].strip()
                    if re.search(r'\d', key_value): # check if there is at least one digit in the key value
                        COUNTER_POTENTIAL_KEYS.append((file_tobe_scanned, key[0]))
                        is_file_clean = False 

            # Add to corresponding lists if company name, your name, or email is mentioned
            for regex, counter in zip(
                [REGEX_COMPANY_NAME, REGEX_YOUR_NAME, REGEX_YOUR_EMAIL],
                [COUNTER_COMPANY_NAME_FILES, COUNTER_YOUR_NAME_FILES, COUNTER_YOUR_EMAIL_FILES]
            ):
                if regex.search(data):
                    counter.append(file_tobe_scanned)
                    is_file_clean = False

            # Add to file walkthrough
            file_walkthrough = add_to_file_walkthrough(is_file_clean, file_tobe_scanned, file_walkthrough)

    except UnicodeDecodeError:
        total_skipped_files += 1
        file_walkthrough.append(f"[SKIPPED non-text file] {file_tobe_scanned}")
        with open(OUT_FILENAME, 'a') as skipped_file:
            skipped_file.write(f"Skipped non-text file: {file_tobe_scanned}\n")

# Calculate the resulting score
consequence_score = (
    COUNTER_COMPANY_URL * SIGNIFICANCE_SCORES['url']
    + len(COUNTER_POTENTIAL_KEYS) * SIGNIFICANCE_SCORES['api_key']
    + len(COUNTER_COMPANY_NAME_FILES) * SIGNIFICANCE_SCORES['company_name']
    + len(COUNTER_YOUR_NAME_FILES) * SIGNIFICANCE_SCORES['name_mention']
    + len(COUNTER_YOUR_EMAIL_FILES) * SIGNIFICANCE_SCORES['email_mention']
)
score = STARTING_SCORE - consequence_score

# calculate the execution time
execution_time = time.time() - start_time

with open(OUT_FILENAME, 'w') as result_file:
    result_file.write(f'Scan started on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC\n')  # write the scan start time at the top
    result_file.write("\nPII Scan Results\n")
    result_file.write("---------------------\n")

    # Display the counter results for each scanned item
    result_file.write(f"\nURLs in codebase containing {COMPANY_NAME}: {COUNTER_COMPANY_URL}") 
    for (counter, significance_score, item) in zip(
        [COUNTER_POTENTIAL_KEYS, COUNTER_COMPANY_NAME_FILES, COUNTER_YOUR_NAME_FILES, COUNTER_YOUR_EMAIL_FILES],
        list(SIGNIFICANCE_SCORES.values())[1:],
        ['Potential API keys', 'Company name mentions', 'Your name mentions', 'Your email mentions']
    ):
        result_file.write(f"\n{item}: {len(counter)}")

        # Display the file paths of the found items
        if counter:
            result_file.write(f"\nFound in:\n")
            for file_path in counter:
                result_file.write(f"- {file_path}\n")
        
    # Display the score, scan time, and file walkthrough
    result_file.write(f"\n\nTotal Security Score: {score}/{STARTING_SCORE}")
    result_file.write('\n\nFile Walkthrough:\n')
    for status in file_walkthrough:
        result_file.write(f"{status}\n")
   
    # Write completed timestamp in the same format
    result_file.write(f'\nScan completed on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC\n')

    # Write total scanning execution time
    result_file.write(f'Total scan time: {execution_time:.5f} seconds\n')

# Output results to console
print(f"Scanned directory: {TREE_TO_SCAN}\n")
print("Results:")
print(f"Total files scanned: {total_scanned_files}")
print(f"Total files skipped (binary/non-readable): {total_skipped_files}\n")
print(f"Company URL mentions: {COUNTER_COMPANY_URL}")
print(f"Potential API keys detected: {len(COUNTER_POTENTIAL_KEYS)}")
print(f"Company name mentions: {len(COUNTER_COMPANY_NAME_FILES)}")
print(f"Your name mentions: {len(COUNTER_YOUR_NAME_FILES)}")
print(f"Your email mentions: {len(COUNTER_YOUR_EMAIL_FILES)}\n")
print(f"Total scan score: {score}/{STARTING_SCORE}\n")
print(f"Total scan time: {execution_time:.5f} seconds\n")
print(f"Scan results exported to: {OUT_FILENAME}\n")
