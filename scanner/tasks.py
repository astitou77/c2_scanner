import socket
import ssl
import subprocess
import json
import time
import signal
import os


# ip_addresses = ['google.com', 'microsoft.com', 'youtube.com', 'facebook.com']
# port = 443  # Standard HTTPS port
pcap_file = "pcap_file.pcap"

def generate_ja4_fingerprint(pcap_file):
    """Run ja4.py script and extract JA4 fingerprints"""
    result = subprocess.run(
        ["python3", "./ja4/python/ja4.py", pcap_file], capture_output=True, text=True
    )
    try:
        return result.stdout # json.loads(result.stdout)
        # print(json.dumps(stix_bundle, indent=4))
        # return json.dumps(result.stdout)
    except json.JSONDecodeError:
        return None

def run_tls_capture(ip, port=443, pcap_file="pcap_file.pcap"):
    """Capture TLS traffic and extract JA4 fingerprints."""
    # Start packet capture using tcpdump
    tcpdump_cmd = f"sudo tcpdump -i en0 tcp port 443 -w {pcap_file}"
    tcpdump_process = subprocess.Popen(tcpdump_cmd, shell=True, preexec_fn=os.setsid)
    time.sleep(2)  # Ensure tcpdump is running before initiating handshakes
    
    tls_results = {}
    
    def initiate_tls_handshake(ip, port=443):
        """Attempt TLS handshake with error handling."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    print(f"TLS Handshake successful: {ip}")
                    return True
        except (socket.timeout, ConnectionRefusedError) as e:
            print(f"Failed TLS handshake ({ip}): {e}")
            return False

    # for ip in ip_addresses:
    tls_results[ip] = initiate_tls_handshake(ip)

    time.sleep(2)
    # Stop packet capture
    os.killpg(os.getpgid(tcpdump_process.pid), signal.SIGTERM)
    print("Packet capture stopped.")

    # Process pcap file and extract JA4 fingerprints
    ja4_fingerprints = generate_ja4_fingerprint(pcap_file)

    # Map fingerprints to successful IPs
    print(ja4_fingerprints, type(ja4_fingerprints))
    # print(ja4_fingerprints['src'])
    processed_results = 't130200_1302_234ea6891581' # {ip: ja4_fingerprints[ip] if tls_results[ip] else None for ip in ip_addresses}

    return processed_results


from celery import shared_task
from .models import SuspiciousIP2
# from my_tls_module import generate_ja4_fingerprint  # Import your function


@shared_task
def update_ja4_fingerprint(ip):
    # 1. Packet Capture during IP handshake
    run_tls_capture(ip, port=443, pcap_file="pcap_file.pcap")

    """Run JA4 fingerprint extraction for a given IP and update DB."""
    pcap_file = f"/path/to/capture_{ip}.pcap"
    
    fingerprint = generate_ja4_fingerprint(pcap_file)
    
    SuspiciousIP2.objects.filter(ip_address=ip).update(ja4_fingerprint=fingerprint)


from .models import SuspiciousIP2
# from .tasks import update_ja4_fingerprint

def process_all_ips():
    """Trigger JA4 fingerprint generation for all Suspicious IPs asynchronously."""
    for ip_obj in SuspiciousIP2.objects.all():
        update_ja4_fingerprint.delay(ip_obj.ip_address)  # Run in Celery background
