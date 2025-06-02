from django.test import TestCase

# Create your tests here.

import requests
from bs4 import BeautifulSoup
from datetime import datetime
from django.db import IntegrityError


import subprocess

def generate_jarm_hash(ip):
    """Runs JARM on the given IP and returns the fingerprint"""
    print("generating the JARM Fingerprint...")
    try:
        result = subprocess.run(["python3", "jarm/jarm.py", ip], capture_output=True, text=True)
        output_lines = result.stdout.strip().split("\n")
        for line in output_lines:
            if line.startswith("JARM: "):
                return line.split("JARM: ")[1].strip()
    except Exception as e:
        print(f"Error generating JARM for {ip}: {e}")
        return None


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

        print("ITEM: ", malware_name, ip_url, ip_address, first_seen)

        data_list.append({
            "malware_name": malware_name,
            "url": ip_url,
            "ip_address": ip_address,
            "first_seen": first_seen,
            "jarm_hash": generate_jarm_hash(ip_address)  # Function to compute hash
        })
    
    return data_list

print(generate_jarm_hash('142.251.32.78'))