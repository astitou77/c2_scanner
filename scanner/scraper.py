import requests
from bs4 import BeautifulSoup
from datetime import datetime
from django.db import IntegrityError
from scanner.models import SuspiciousIP

def scrape_data():
    url = "https://tracker.viriback.com/"  # Replace with actual source URL
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    tbody = soup.find("tbody", {"id": "developers"})
    data_list = []

    for row in tbody.find_all("tr"):
        cols = row.find_all("td")
        malware_name = cols[0].text.strip()
        ip_url = cols[1].find("a")["href"]
        ip_address = cols[2].text.strip()
        first_seen = datetime.strptime(cols[3].text.strip(), "%d-%m-%Y")

        data_list.append({
            "malware_name": malware_name,
            "url": ip_url,
            "ip_address": ip_address,
            "first_seen": first_seen,
            "jarm_hash": generate_jarm_hash(ip_address)  # Function to compute hash
        })
    
    return data_list

def save_to_database():
    data_list = scrape_data()
    for entry in data_list:
        if not SuspiciousIP.objects.filter(malware_name=entry["malware_name"], ip_address=entry["ip_address"]).exists():
            try:
                SuspiciousIP.objects.create(**entry)
            except IntegrityError:
                print(f"Duplicate skipped: {entry}")

def generate_jarm_hash(ip):
    """Mock function to compute a JARM fingerprint"""
    return f"JARMMMSSDJDDDSDS"  # Replace with actual JARM computation
