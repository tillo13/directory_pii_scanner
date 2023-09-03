# PII Directory Scanner

This script is designed to perform a basic scan through a designated directory, specifically looking for Personally Identifiable Information (PII) looking for URLs, mentions, and potential API keys.  The idea here was more for my own benefit to validate I didn't leave any PII data for me or the company in any of the codebase I was saving to Github, this did the trick for me, your results/Security team standards may vary, so certainly don't use it as definitely correct for your use case.

## How It Works

The Script works by simultaneously opening and reading all the files under the given directory, then hunting for pattern matches that correspond to URLs, potential API keys, specific company names, a specific individual's name, and email address. Skips include defined directories, binary/non-readable files, and specific files. 

The script then compiles all the results, calculates a security score based on predefined weights of each PII type (that you can set yourself based on your needs), and writes the results and file status walkthrough into an output file. The text results are also printed to the console.

Here are the key components of the scanner:

- **URLs**: This scans for http and https URLs which could potentially lead to exposed web services.
- **Potentially exposed API keys**: These are variable assignations that include the term "key".
- **Company Name mentions**: This counts the occurrence of a pre-defined company name in the codebase.
- **Your Name and Email mentions**: This scans for occurrences of a specific individual's name and email, which might have been mistakenly included in the codebase.

Each finding has a pre-defined significance score that impacts the overall (made up, but valid-ish) security score. For example, detection of an API key significantly lowers the security score due to the massive risk of exposed application interface keys.

## How to Use

1. Clone the repository to your local machine.
2. Open the script in your favorite code editor and set your parameters like file paths, company name, your name, and email.
3. Run the script in your terminal with `python your_script_name.py`.
4. Look at it yourself, but certainly don't think of it as anything official --check with your local Security folks if you need more detail and modify at will.  

The script will create an output file in the same directory with detailed results of the scan, including the file paths of potential security issues discovered. It also prints a summary of the results to the console.

