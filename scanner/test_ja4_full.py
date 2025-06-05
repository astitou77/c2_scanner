import os
import django
import sys
# Set up Django environment
sys.path.append("/Users/adnane/Desktop/c2_scanner")  # Adjust path accordingly
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "c2_scanner.settings")
django.setup()

import socket
import ssl
import subprocess
import json
import time
import signal

# 1. Start packet capture using tcpdump | generate *.pcap file
tls_results = {}
pcap_file = "pcap_filezzz.pcap"

# Ensure the file is deleted before starting a new capture
if os.path.exists(pcap_file):
    os.remove(pcap_file)

tcpdump_cmd = f"sudo tcpdump -i en0 tcp port 443 -w {pcap_file}"  # *** check README.md 'pcap' sudo permissions ***
tcpdump_process = subprocess.Popen(tcpdump_cmd, shell=True, preexec_fn=os.setsid)

time.sleep(2)  # Ensure tcpdump is running before initiating handshakes

# 2. initiate TLS handshake(s) to threat IP's | recorded in *.pcap file
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


from scanner.models import SuspiciousIP
brah = ['https://www.google.com', 'lapresse.ca', 'youtube.com']
for threat in SuspiciousIP.objects.all():
    domain = threat.malware_name # .ip_address
    print(f"Attempting TLS handshake with {domain}...")
    if initiate_tls_handshake(domain):
        tls_results[domain] = True
# for threat in brah: # SuspiciousIP.objects.all()   2.1 loop over each threat IP address
#     print('Initiate TLS Handshake with Threat IP\t...\t', threat) # threat.ip_address)
#     tls_results[threat] = initiate_tls_handshake(threat) # threat.ip_address)
print('Handshakes completed...', tls_results)


# 3. Stop packet capture
time.sleep(2) # wait few minutes to save *.pcap file
os.killpg(os.getpgid(tcpdump_process.pid), signal.SIGTERM)
print("Packet capture stopped.")


# 4. generate JARM fingerprint
def generate_jarm_fingerprint(domain):
    try:
        result = subprocess.run(
            ["python3", "./scanner/jarm/jarm.py", domain], 
            capture_output=True, text=True, check=True
        )
        output_lines = result.stdout.split("\n")  # Split the output into lines

        for line in output_lines:
            if line.startswith("JARM:"):
                return line.split(": ")[1].strip()  # Extract and return the hash

    except subprocess.CalledProcessError as e:
        print(f"Error running jarm.py: {e}")
        return None

for item in SuspiciousIP.objects.all():
    jarm_hash = generate_jarm_fingerprint(item.malware_name)
    SuspiciousIP.objects.filter(malware_name=item.malware_name).update(jarm_hash = jarm_hash)
    # item.jarm_hash = jarm_hash

# 5. Use ja4.py to extract JA4+ Signatures from *.pcap | for IP's that Successfully TLS Handshaked
import subprocess
import json

def generate_ja4_fingerprint(pcap_file):
    try:
        result = subprocess.run(
            ["python3", "./scanner/ja4/python/ja4.py", pcap_file], 
            capture_output=True, text=True, check=True
        )
        
        # Attempt to parse output as JSON
        # fixed_result = result.stdout.encode().decode("unicode_escape")  # Handle escape sequences
        raw_output = result.stdout.strip().split("\n")  # Split by lines
        fixed_result2 = "[" + ",".join(raw_output) + "]"  # Join with commas
        fixed_result = fixed_result2.replace("'", '"').replace("}{", "},{")
        
        try:
            print("\n GOOOD !!! \n")
            return json.loads(fixed_result)
        except json.JSONDecodeError:
            print("\n BAAAAAD !! \n")
            return fixed_result  # Return raw output if JSON parsing fails

    except subprocess.CalledProcessError as e:
        print(f"Error running ja4.py: {e}")
        return None

fingerprint_data = generate_ja4_fingerprint(pcap_file)
# print(fingerprint_data)

# Loop through each fingerprint entry and update SuspiciousIP model
# Update SuspiciousIP objects with JA4 hash
for entry in fingerprint_data:
    src_ip = entry.get('domain')
    ja4_hash = entry.get('JA4S')

    print(entry['src'], entry['domain'], entry['JA4.1'], entry['JA4_o.1'], entry['JA4_o.1'], entry['JA4S'])

    # src_ip = entry['src']
    # ja4_hash = entry['JA4.1']

    if src_ip in tls_results:
        SuspiciousIP.objects.filter(malware_name=src_ip).update(ja4_hash=ja4_hash)
        print(f"Updated {src_ip} with JA4 hash: {ja4_hash}")

print("Script completed successfully!!!!!")

