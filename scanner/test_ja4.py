import socket
import ssl
import subprocess
import json
import time
import signal
import os

ip_addresses = ['google.com', 'microsoft.com', 'youtube.com', 'facebook.com']
port = 443  # Standard HTTPS port
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

def run_tls_capture():
    """Capture TLS traffic and extract JA4 fingerprints."""
    # Start packet capture using tcpdump
    tcpdump_cmd = f"sudo tcpdump -i en0 tcp port 443 -w {pcap_file}"
    tcpdump_process = subprocess.Popen(tcpdump_cmd, shell=True, preexec_fn=os.setsid)
    time.sleep(2)  # Ensure tcpdump is running before initiating handshakes
    
    tls_results = {}
    
    def initiate_tls_handshake(ip):
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

    for ip in ip_addresses:
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

# Run the process
result = run_tls_capture()
print(json.dumps(result, indent=4))
