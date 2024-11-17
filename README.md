# CyberSecurity-Intern-Week1
It includes setting up a secure virtual environment, performing packet analysis with Wireshark, implementing password hashing and salting in Python, and identifying common web app security threats from OWASP Top 10.
Overview
This repository contains the tasks completed during the first week of my Cybersecurity internship. The tasks include an introduction to network security, basic security practices, packet analysis using Wireshark, password security through hashing, and web application security testing using Burp Suite. These activities help lay the foundation for understanding critical cybersecurity concepts and techniques.

Tasks Completed
1. Cybersecurity Fundamentals
CIA Triad: Implemented the principles of Confidentiality, Integrity, and Availability to understand their significance in securing systems and data.
Types of Cyberattacks: Learned about common attack vectors like phishing, malware, and DoS attacks, and their potential impact on businesses.
Network Security: Configured basic network security settings using firewalls, IDS, and secure user authentication practices.
2. Setting Up a Secure Virtual Environment
VMware Setup: Configured VMware as the primary virtual machine platform for security tasks.
Kali Linux Installation: Installed Kali Linux, a popular distribution for penetration testing and security analysis.
3. Network Security Basics: Packet Analysis
Wireshark: Installed Wireshark on Kali Linux and captured packets during a website visit to analyze network traffic and understand the role of different protocols (HTTP, TCP/UDP, DNS).
Packet Capture: Identified key elements such as source and destination IPs, protocols, and ports used during the packet exchange.
4. Password Security and Hashing
Python Script for Password Hashing: Wrote a Python script that hashes passwords using the SHA-256 algorithm with added salting to secure user credentials.
Salting: Learned how salting enhances password security by making password hashes unique and harder to reverse.
5. Web Application Security Testing with Burp Suite
Burp Suite Setup: Configured Burp Suite for web application penetration testing.
Interception of HTTP Requests: Used Burp Suite’s proxy tool to intercept and modify HTTP requests and responses between the browser and the server.
Active Scanning: Conducted an active scan to identify common vulnerabilities like SQL injection and XSS on a test web application.
Spidering: Used Burp Suite's spider tool to map out a website's structure and identify hidden pages and functionality.
6. Basic Threat Identification Using OWASP Top 10
Injection Attacks: Implemented basic SQL injection techniques to understand how vulnerabilities can be exploited by attackers.
Broken Authentication: Examined authentication weaknesses and potential exploits, such as session hijacking.
Sensitive Data Exposure: Identified risks associated with improperly secured sensitive data.
Broken Access Control: Studied the impact of improper access control mechanisms and how they can be exploited.
XSS (Cross-Site Scripting): Learned the basics of XSS attacks and their potential impact on user security.
Key Learnings
Network Traffic Analysis: Gained a deeper understanding of how network traffic is captured and analyzed to detect potential security issues.
Password Protection: Developed skills in securing passwords using modern techniques like hashing and salting.
Web Application Security: Gained hands-on experience with Burp Suite, a leading tool for web application penetration testing, to identify and exploit security vulnerabilities.
OWASP Top 10 Vulnerabilities: Recognized the importance of securing web applications against common security flaws outlined in the OWASP Top 10.
Tools Used
Kali Linux: The primary platform used for penetration testing and analysis.
Wireshark: A powerful tool for capturing and analyzing network traffic.
Burp Suite: Used for web application security testing, including interception, scanning, and vulnerability identification.
Python: Used to write scripts for password hashing and salting.
