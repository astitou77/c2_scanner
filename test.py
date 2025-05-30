print("Hello C2 Scanner !")

import requests
from bs4 import BeautifulSoup

url = "https://tracker.viriback.com/"
response = requests.get(url)
soup = BeautifulSoup(response.text, "html.parser")

# Example: Extract IPs and Ports (Modify based on actual HTML structure)
suspicious_pairs = []
for row in soup.find_all("tr"):
    cols = row.find_all("td")
    if len(cols) >= 2:
        ip = cols[0].text.strip()
        port = cols[1].text.strip()
        suspicious_pairs.append((ip, port))

print(suspicious_pairs)