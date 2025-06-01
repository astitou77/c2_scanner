# 1. Command & Control (C2) Servers : Threat Identification !

## 1.1 What is C2 Servers ? 
A command and control (C2) server is a central hub used by attackers to remotely control compromised systems after a cyberattack. It acts as the communication link between the attacker and the infected devices, allowing them to issue commands, collect data, and coordinate malicious activities. It is the "brain" of a cyberattack, directing the actions of malware on compromised machines. 

One of the primary functions of a C2 server is to facilitate the download of additional malware onto compromised devices. This can include:
- Trojans: Used to create backdoors for future access.
- Keyloggers: To capture and transmit keystrokes, allowing attackers to steal credentials.
- Rootkits: To hide the presence of malware and maintain persistent access.
- Spyware: To monitor user activity and exfiltrate sensitive information.
- Ransomware: Encrypts files on the victim’s system and demands a ransom for the decryption key.

## 1.2 How to Manage Threats from C2 Servers
Protecting against and hunting for C2 (Command and Control) traffic involves a combination of proactive defense measures, continuous monitoring, and advanced threat detection techniques. Here’s a detailed guide on how companies can effectively manage these tasks:
1. **Network Traffic Analysis**
    - Deep Packet Inspection (DPI): Analyze packets as they pass through an inspection point. Use DPI-capable firewalls and intrusion detection/prevention systems (IDS/IPS).
    - Anomaly Detection: Employ machine learning algorithms and behavioral analysis tools to identify unusual traffic patterns that may indicate C2 communication.
2. **Endpoint Protection**
    - Endpoint Detection and Response (EDR): Deploy EDR solutions that can detect malware behavior, track C2 connections, and automatically isolate compromised endpoints.
    - Anti-malware and Antivirus: Regularly update antivirus definitions and use heuristic analysis to detect new and unknown malware strains.
3. **Threat Intelligence Integration**
    - Threat Intelligence Feeds: Integrate threat intelligence feeds into security information and event management (SIEM) systems to automatically block or flag communications with known malicious C2 servers.
    - Collaborative Threat Sharing : Participate in information sharing and analysis centers (ISACs) and use platforms like STIX/TAXII for automated threat intelligence sharing.
4. **Network Segmentation and Isolation**
    - Network Segmentation : Dividing a network into segments. Implement VLANs, firewalls, and access control lists (ACLs) to enforce strict segmentation.
    - Isolation of Critical Assets : Isolating critical systems from the rest of the network. Use dedicated, physically isolated networks for critical infrastructure and apply stringent access controls.
5. **DNS Filtering and Analysis**
    - DNS Sinkholing : Configure DNS sinkholes to intercept and analyze queries to known malicious domains.
    - DNS Traffic Monitoring : Use DNS security solutions and logs to detect and investigate suspicious DNS queries.
6. **Email Security**
    - Email Filtering : Employ advanced email security solutions that use spam filters, attachment scanning, and URL analysis.
    - Phishing Awareness Training : Conduct regular training sessions and simulated phishing exercises to enhance awareness.
8. **Log Analysis and SIEM**
    - Centralized Log Management : Use a centralized log management solution and SIEM to correlate and analyze security events.
    - Automated Incident Response : Configure SIEM and EDR tools to automatically block suspicious IPs, isolate infected systems, and alert security teams.
10. **Advanced Analytics and Machine Learning**
    - Behavioral Analytics : Monitoring the behavior of users and devices to identify deviations that may indicate compromise.
    - User and Entity Behavior Analytics (UEBA) : Integrate UEBA solutions with SIEM for enhanced detection capabilities.
11. **Regular Threat Hunting**
    - Proactive Threat Hunting : Actively searching for signs of C2 activity within the network before automated systems detect them.

*** source : https://www.malwarepatrol.net/command-control-servers-c2-servers-fundamentals/

# 2. This project's purpose is to 
- scrape known threats across the web
- dfdf
- dfdf

## 0. Setup Django Project
> Create a Python Virtual Environment [ Avoids messing with Python instance used by the OS ]
* python -m venv .venv </br>
* source .venv/bin/activate </br>
* pip install django requests </br>

> start the 'c2_scanner' Django project
* django-admin startproject c2_scanner </br>
* cd c2_scanner </br>

    <b> add the 'scanner' Django application </b>
    python manage.py startapp scanner </br>
    ### under 'c2_scanner/settings.py', register the 'scanner' app in the 'c2_scanner' project
    INSTALLED_APPS = [ ..., 'scanner', ] </br>

    <b> under 'scanner/models.py:' Define the Django models (Database/Tables) </b>
    Table 'models.Model.<myTable>' - [ ex.: store IPs from Viriback C2 Tracker ] </br>
        &nbsp;&nbsp;&nbsp;&nbsp; models.Model.<myTable>.malware_name </br>
        &nbsp;&nbsp;&nbsp;&nbsp; models.Model.<myTable>.url </br>
        &nbsp;&nbsp;&nbsp;&nbsp; models.Model.<myTable>.ip_address </br>
        &nbsp;&nbsp;&nbsp;&nbsp; models.Model.<myTable>.first_seen </br>
    <b> migrate (update) the Django sqlite databases </b>
    python manage.py makemigrations </br>
    python manage.py migrate </br>

    <b> under '/c2_scanner/urls.py' ---> '/scanner/urls.py' setup URL rootings </b>
    urlpatterns = [ path('', include('scanner.urls')), ] </br>
    urlpatterns = [ path('scraped/', view_BLAH_BLAH, name='scraped'), ] </br>

    <b> under 'scanner/views.py' setup the ***DJANGO MAGIC*** </b>
    def view_BLAH_BLAH(request):  </br>
        &nbsp;&nbsp;&nbsp;&nbsp; threats = .models.<myTable>.objects.all() </br>
        &nbsp;&nbsp;&nbsp;&nbsp; return render(request, 'scanner/<scraped>.html', {'threatsss': threats})

    <b> under 'scanner/templates/scanner/<myTemplate>.html' create the webpage to display </b>
    {% for threat in threatsss %} </br>
        &nbsp;&nbsp;&nbsp;&nbsp; {{ threat.malware_name }} </br>
        &nbsp;&nbsp;&nbsp;&nbsp; {{ threat.url }} </br>
        &nbsp;&nbsp;&nbsp;&nbsp; {{ threat.ip_address }} </br>
        &nbsp;&nbsp;&nbsp;&nbsp; {{ threat.first_seen }} </br>
    {% endfor %}

    <b> Run the project </b>
    python manage.py runserver 0.0.0.0:8000     # start service ; Open ---> http://127.0.0.1:8000

    <b> Create Django Admin Console superuser </b>
    python manage.py createsuperuser            # adnane / I..1    |  Login --->  http://127.0.0.1:8000/admin



 </br>

## 1. Scrapy : scrape list of IPs/Ports
    1.0 Create 'SuspiciousIP' Table in models.py
            1.0.0 Migrate changes
                python manage.py makemigrations scanner
                python manage.py migrate
            1.0.1 Test a 'https://tracker.viriback.com/' input to the Table in the Django shell
                python manage.py shell
                    > from scanner.models import SuspiciousIP
                    > from datetime import datetime
                    > test_entry = SuspiciousIP.objects.create(
                        malware_name="Supershell", 
                        url="http://38.12.252.74:8888/supershell/login/", 
                        ip_address="38.12.252.74", 
                        first_seen=datetime.strptime("30-05-2025", "%d-%m-%Y")
                        )
                    > print(f"Added: {test_entry}")
                python manage.py dbshell
                    > SELECT * FROM scanner_suspiciousip;


    1.1 'Start SCAN' Button
    1.2 DISPLAY IPs:Ports in a Bootstrap Formatted List
        // instead of an IP Scan form, how to scrape IP:port pairs from online sites like 'https://tracker.viriback.com/' and use those values

2. C2 Threats Databases : Censys + Shodan.io + VirusTotal
3. Zgrab2 : Scan locally | JA4+ = Fingerprint Servers independent of IP:Port used
4. Django : Block / Allow 

<h2> AWS VM </h2>

ssh -i "/Users/adnane/Downloads/VM-Key-Mullvad_VPN.pem" ubuntu@15.157.114.18

<h1> Running the app </h1>

nohup python manage.py runserver 0.0.0.0:8000 &
