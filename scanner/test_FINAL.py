import os
import django
import sys
# Set up Django environment
sys.path.append("/Users/adnane/Desktop/c2_scanner")  # Adjust path accordingly
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "c2_scanner.settings")
django.setup()

from scanner.models import SuspiciousIP
import os
import ssl
import socket
import subprocess
import json
import time
import signal

# Start packet capture
pcap_file = "pcap_filezzz.pcap"
if os.path.exists(pcap_file):
    os.remove(pcap_file)

tcpdump_cmd = f"sudo tcpdump -i en0 tcp port 443 -w {pcap_file}"
tcpdump_process = subprocess.Popen(tcpdump_cmd, shell=True, preexec_fn=os.setsid)

time.sleep(2)  # Give time for tcpdump to start

# Perform TLS handshakes for SuspiciousIP objects
tls_results = {}

def initiate_tls_handshake(ip):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                print(f"TLS Handshake successful: {ip}")
                return True
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"Failed TLS handshake ({ip}): {e}")
        return False

for threat in SuspiciousIP.objects.all():
    ip = threat.ip_address
    print(f"Attempting TLS handshake with {ip}...")
    if initiate_tls_handshake(ip):
        tls_results[ip] = True

# Stop packet capture
time.sleep(2)
os.killpg(os.getpgid(tcpdump_process.pid), signal.SIGTERM)

# Generate JA4+ fingerprints
def generate_ja4_fingerprint(pcap_file):
    try:
        result = subprocess.run(
            ["python3", "./scanner/ja4/python/ja4.py", pcap_file],
            capture_output=True, text=True, check=True
        )
        raw_output = result.stdout.strip().split("\n")
        fixed_result = "[" + ",".join(raw_output) + "]".replace("'", '"').replace("}{", "},{")
        
        return json.loads(fixed_result)
    except subprocess.CalledProcessError as e:
        print(f"Error running ja4.py: {e}")
        return None

fingerprint_data = generate_ja4_fingerprint(pcap_file)

# Update SuspiciousIP objects with JA4 hash
for entry in fingerprint_data:
    src_ip = entry.get('src')
    ja4_hash = entry.get('JA4.1')

    if src_ip in tls_results:
        SuspiciousIP.objects.filter(ip_address=src_ip).update(ja4_hash=ja4_hash)
        print(f"Updated {src_ip} with JA4 hash: {ja4_hash}")

print("Script completed successfully!")
