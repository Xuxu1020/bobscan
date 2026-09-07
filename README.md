BobScan

Setup:
1. Clone the repository

git clone https://github.com/Xuxu1020/bobscan.git

2. Install dependencies

python -m pip install -r requirements.txt



How to run:
1. Save to HTML report:

python -m bobscan http://example.com -o report.html

2. Save to JSON report:

python -m bobscan http://example.com -o report.json

3. Passive mode, no active scanning:

python -m bobscan http://example.com --no-active

4. Show help:

python -m bobscan -h

