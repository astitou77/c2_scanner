import requests
from bs4 import BeautifulSoup
from datetime import datetime

# Example: Fetch the webpage (replace with the actual URL)
url = "https://tracker.viriback.com/"  # Replace with the actual webpage URL
response = requests.get(url)
soup = BeautifulSoup(response.text, "html.parser")

# Find the table body
tbody = soup.find("tbody", {"id": "developers"})

# List to store scraped data
data_list = []

# Iterate over table rows
for row in tbody.find_all("tr"):
    cols = row.find_all("td")
    malware_name = cols[0].text.strip()  # Extract malware name
    ip_url = cols[1].find("a")["href"]  # Extract URL
    ip_address = cols[2].text.strip()  # Extract IP
    first_seen = datetime.strptime(cols[3].text.strip(), "%d-%m-%Y")  # Convert date

    # Append to the list
    data_list.append({
        "malware_name": malware_name,
        "url": ip_url,
        "ip_address": ip_address,
        "first_seen": first_seen
    })

# Print the extracted data
for entry in data_list:
    print(entry)


from django.db import IntegrityError
from scanner.models import SuspiciousIP

for entry in data_list:
    if not SuspiciousIP.objects.filter(malware_name=entry["malware_name"], ip_address=entry["ip_address"]).exists():
        try:
            SuspiciousIP.objects.create(
                malware_name=entry["malware_name"],
                url=entry["url"],
                ip_address=entry["ip_address"],
                first_seen=entry["first_seen"]
            )
        except IntegrityError:
            print(f"Duplicate entry skipped: {entry}")


