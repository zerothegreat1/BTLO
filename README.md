# BTLO
Blue Team Labs Online: Network Analysis- Malware Compromise

### Scenario

As a SOC Analyst at Umbrella Corporation, you are tasked with investigating a SIEM alert for connections to a known malicious domain originating from Sara's computer. Sara is an Accountant who receives numerous emails from customers daily. Upon reviewing the email gateway logs, no immediately suspicious emails were identified. However, Sara mentioned that a customer sent her an invoice with a document containing a macro, which she opened, causing her program to crash. The SOC team has retrieved a PCAP file for further analysis.

### Objective

The objective of this lab exercise is to analyze a PCAP file to identify signs of malicious activity from a suspected phishing attack. The analysis involves inspecting network traffic, identifying indicators of compromise (IOCs), and documenting the findings.

### Overview

This project demonstrates practical skills in network traffic analysis, threat detection, and incident response. The scenario involves investigating a suspected phishing attack where a user opened a malicious document, leading to connections with a known malicious domain.

### Skills Learned

- Network Traffic Analysis
- Threat Detection and Analysis
- Incident Response
- Malware Analysis
- Communication and Reporting

### Tools Used

<div>
    <img src="https://img.shields.io/badge/-Wireshark-1679A7?&style=for-the-badge&logo=Wireshark&logoColor=white" />
    <img src="https://img.shields.io/badge/-Zeek-777BB4?&style=for-the-badge&logo=Zeek&logoColor=white" />
    <img src="https://img.shields.io/badge/-VirusTotal-39457E?&style=for-the-badge&logo=VirusTotal&logoColor=white" />
    <img src="https://img.shields.io/badge/-Kali_Linux-557C94?&style=for-the-badge&logo=Kali%20Linux&logoColor=white" />
    <img src="https://img.shields.io/badge/-Python-3776AB?&style=for-the-badge&logo=Python&logoColor=white" />
</div>

### Project Structure

- PCAP Analysis: Steps and methods used to analyze the PCAP file.
- Incident Response Plan: Documenting the steps taken to isolate and mitigate the threat.
- Findings Report: Detailed report on the findings from the analysis.

### Getting Started

### Prerequisites
- Wireshark installed on your system.
- Basic understanding of network protocols.
- Familiarity with command-line tools.

### Instructions

#### Load the PCAP File in Wireshark

1. Open Wireshark and load the provided PCAP file.

  <img width="1280" alt="Screen Shot 2024-05-16 at 12 17 53 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/c0980685-1500-4d6d-bef7-5448ef73a3e3">

#### Filter Traffic

2. Use filters to isolate traffic to/from the known malicious domain.
- Example Wireshark filter: ip.addr == [Malicious IP Address]

<img width="1280" alt="Screen Shot 2024-05-16 at 12 32 58 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/46b9f903-9422-4dd2-aa31-55c6bb3124b5">
  

#### Analyze DNS Queries

3. Look for DNS queries to the malicious domain.

<img width="1280" alt="Screen Shot 2024-05-16 at 12 44 20 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/ee055f45-2b78-455c-9023-187625f410d0">

### Inspect HTTP/HTTPS Traffic

4. Examine the payload of HTTP/HTTPS requests and responses.
  <img width="1280" alt="Screen Shot 2024-05-16 at 12 43 18 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/8cc9d523-54f7-4445-91e4-313742621336">
* ref img Client Handshake

<img width="1280" alt="Screen Shot 2024-05-14 at 3 16 11 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/c4b3ef9f-85e0-43dc-9b68-6095c18a6f87">

5. Use filters like http.host contains "[Malicious Domain]".

<img width="1280" alt="Screen Shot 2024-05-14 at 3 03 09 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/0bf55ffc-3bd7-43fc-ad8e-39bfb5765ce8">
* ref img Malicious Domain Name

<img width="1280" alt="Screen Shot 2024-05-14 at 3 03 30 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/76cf399b-e685-4cb8-acdd-d9d3014839a0">
* ref img Use VirusTotal to verify malicious domain

### Identify Suspicious Activity

6. Document any suspicious patterns or anomalies in the traffic.

<img width="1280" alt="Screen Shot 2024-05-16 at 12 39 06 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/6fcebfd2-34cc-41ef-a609-559fbfe130fb">
* ref img Suspicious img request

<img width="1280" alt="Screen Shot 2024-05-16 at 1 00 29 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/464a970f-12ad-48a2-b857-f3c3e0e802b3">
*ref img rar file

### Analysis and Findings

#### Initial Observations: Summary of the initial traffic patterns noticed.

<img width="1280" alt="Screen Shot 2024-05-16 at 12 20 53 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/fee85d19-83cb-47eb-98cb-fce12d705f12">


### Detailed Analysis
1. DNS Query Analysis

- Identified multiple DNS queries to a known malicious domain.

<img width="1280" alt="Screen Shot 2024-05-16 at 12 44 20 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/c0ea520c-e300-4bac-b1a7-4a2bb03c58bd">


- Filter used: event_type == "alert"

<img width="1280" alt="Screen Shot 2024-05-14 at 3 33 00 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/3b2ab9c2-94ef-4d8f-bc64-0f95c8a591fa">
* ref img Used Zui query pcap alerts



2. HTTP/HTTPS Traffic Analysis

<img width="1280" alt="Screen Shot 2024-05-16 at 12 58 25 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/9f72da14-402d-4123-9a1b-c285b747d35b">

- Detected HTTP requests to cochrimato.com shortly after the DNS queries.
  <img width="1280" alt="Screen Shot 2024-05-14 at 3 03 09 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/725a16c2-bf4f-4a97-9723-0f140c6f2f88">
- Filter used: http.host contains "cochrimato.com"
<img width="1280" alt="Screen Shot 2024-05-14 at 3 03 30 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/a9bb763a-a53c-4049-a074-a0d2041375c6">

<img width="1280" alt="Screen Shot 2024-05-14 at 3 04 19 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/cd2920ba-ba8d-4e9b-b50c-9d11f42fb0d8">


- Payload analysis indicated potential download of a malicious payload.

<img width="1280" alt="Screen Shot 2024-05-16 at 1 00 29 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/35739b0d-7fca-4b44-b7d6-d6e7f9b080aa">

3. Anomalous Patterns
- Unusual spike in traffic volume to the malicious domain.
- Repeated connection attempts within short intervals.

#### Indicators of Compromise (IOCs)
- Malicious Domain: cochrimato.com
- Malicious IP Address: 192.168.1.100
- Suspicious File Downloads: HTTP requests leading to .exe downloads from the malicious domain.

<img width="1280" alt="Screen Shot 2024-05-14 at 3 33 00 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/42050c2d-88a6-4fbc-8751-1f07d96ee87a">


<img width="1280" alt="Screen Shot 2024-05-16 at 1 17 19 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/543d4aca-86b3-460e-ae7b-fc932cdfeee0">
* ref img Use CLI to generate a file hash

<img width="1280" alt="Screen Shot 2024-05-14 at 3 52 59 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/a2648db1-a643-420b-9aa2-64597573f526">
*ref img search file hash via VirusTotal

### Mitigation Steps
1. Isolate Affected Systems
- Immediately isolate the systems showing signs of compromise to prevent further spread.

2. Block Malicious Domains
- Update firewall and DNS settings to block traffic to cochrimato.com.

3. Conduct Full Malware Scan
- Perform a comprehensive malware scan on affected systems using updated antivirus tools.

4. Review and Update Security Policies
- Ensure all email filtering systems are updated to catch similar phishing attempts.
- Conduct security awareness training for users to recognize phishing attacks.



  
### Conclusion
The analysis of the PCAP file revealed a phishing attack leading to malware compromise. By identifying DNS queries and HTTP requests to a known malicious domain, we isolated indicators of compromise and mitigated the threat. This exercise highlights the importance of network traffic analysis, timely incident response, and continuous security training in safeguarding organizational assets. Skills gained in this exercise, such as using Wireshark for packet analysis and understanding threat patterns, are crucial for a career as a SOC Analyst.





<img width="1278" alt="Screen Shot 2024-05-15 at 2 09 15 PM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/096517ac-2545-4f31-9d82-95112653f0dd">


<img width="1280" alt="Screen Shot 2024-05-14 at 3 58 26 AM" src="https://github.com/zerothegreat1/BTLO/assets/164509453/2efb4221-379c-41c3-b5b0-7ac51035fbc6">
