import re
# import ja3
# import ja4

# Read log file and extract IP and TLS details
def parse_tomcat_log(file_path):
    log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*TLS details here')  # Modify as needed
    fingerprints = {}

    with open(file_path, "r") as f:
        for line in f:
            print(line)
            match = log_pattern.search(line)
            if match:
                ip = match.group(1)
                print(ip)
                # tls_data = extract_tls_data(line)  # Implement extraction logic
                # ja3_fingerprint = ja3.compute(tls_data)
                # ja4_fingerprint = ja4.compute(tls_data)

                fingerprints[ip] = ip # {"JA3": ja3_fingerprint, "JA4": ja4_fingerprint}

    return fingerprints


# get IPs from TOMCAT Access Log ! Works !
import re

def extract_ips_from_log(log_file):
    """Extract unique IP addresses from a Tomcat access log"""
    ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")  # Basic regex for IPs
    ips = set()

    with open(log_file, "r") as file:
        for line in file:
            match = ip_pattern.search(line)
            if match:
                ips.add(match.group(1))

    return list(ips)


# Example usage
log_path = "/Users/adnane/Desktop/c2_scanner/scanner/access_log.txt"
fingerprints = extract_ips_from_log(log_path)
print(fingerprints)




