import os
import django
import sys
import socket
import ssl
import subprocess
import json
import time
import signal

# Set up Django environment
sys.path.append("/Users/adnane/Desktop/c2_scanner")  # Adjust path accordingly
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "c2_scanner.settings")
django.setup()

from scanner.models import SuspiciousIP

# 1. Start packet capture using tcpdump | generate *.pcap file
tls_results = {}
pcap_file = "pcap_filezzz.pcap"

# Ensure the file is deleted before starting a new capture
if os.path.exists(pcap_file):
    os.remove(pcap_file)

tcpdump_cmd = f"sudo tcpdump -i en0 tcp port 443 -w {pcap_file}"  # *** check README.md 'pcap' sudo permissions ***
tcpdump_process = subprocess.Popen(tcpdump_cmd, shell=True, preexec_fn=os.setsid)

time.sleep(2)  # Ensure tcpdump is running before initiating handshakes

# 2. Initiate TLS handshake(s) to threat IPs | Recorded in *.pcap file
def initiate_tls_handshake(ip, port=443):
    """Attempt TLS handshake with error handling."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                print(f"\t---> TLS Handshake successful: {ip}")
                return True
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"\t---> Failed TLS handshake ({ip}): {e}")
        return False

for threat in SuspiciousIP.objects.all():
    domain = threat.malware_name
    print(f"Attempting TLS handshake with {domain}...")
    if initiate_tls_handshake(domain):
        tls_results[domain] = True

print('Handshakes completed...', tls_results)

# 3. Stop packet capture
time.sleep(2)  # Wait a few seconds to save *.pcap file
os.killpg(os.getpgid(tcpdump_process.pid), signal.SIGTERM)
print("Packet capture stopped.")

# 4. Generate JA3 fingerprints from the PCAP file
def generate_ja3_fingerprint(pcap_file):
    try:
        result = subprocess.run(
            ["python3", "./scanner/ja3/python/ja3.py", pcap_file], 
            capture_output=True, text=True, check=True
        )
        
        raw_output = result.stdout.strip().split("\n")  # Split by lines
        fixed_result = "[" + ",".join(raw_output) + "]"  # Format as JSON
        
        try:
            print("\n Extracting JA3 fingerprints... \n")
            return json.loads(fixed_result)
        except json.JSONDecodeError:
            print("\n JSON parsing failed, returning raw output. \n")
            return fixed_result  

    except subprocess.CalledProcessError as e:
        print(f"Error running ja3.py: {e}")
        return None

# 5. Process JA3 fingerprints and update SuspiciousIP model
fingerprint_data = generate_ja3_fingerprint(pcap_file)

print(fingerprint_data)

if fingerprint_data:
    for entry in fingerprint_data:
        src_ip = entry.get('src_ip')
        ja3_hash = entry.get('JA3')

        if src_ip in tls_results:
            SuspiciousIP.objects.filter(malware_name=src_ip).update(ja3_hash=ja3_hash)
            print(f"Updated {src_ip} with JA3 hash: {ja3_hash}")

print("JA3 fingerprint extraction completed successfully!")
