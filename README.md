# Malicious-PDF-Aanlystics-Lab

---

# **Malware Analysis Portfolio**

## **Overview**
Welcome to my Malware Analysis Portfolio! This repository showcases my ability to analyze and document real-world malware samples sourced from [MalwareBazaar](https://bazaar.abuse.ch/). The focus is on dissecting malicious files to understand their functionality, behavior, and potential impact, while presenting findings in a structured, professional format.

## **What You’ll Find**
Each analysis includes:
- **Static Analysis**: Extracting metadata, analyzing strings, and identifying file characteristics.
- **Dynamic Analysis**: Observing real-time behavior in a sandbox environment, such as process creation, file modifications, and network activity.
- **Indicators of Compromise (IOCs)**: Hashes, domains, IPs, registry keys, and other forensic artifacts.
- **Mitigation Recommendations**: Practical advice for detection and prevention.

## **Methodology**
The analyses follow a structured process modeled after professional cybersecurity workflows:
1. **Pre-Analysis Setup**: Preparing an isolated lab environment with industry-standard tools.
2. **Sample Triage**: Gathering initial insights through quick hash and metadata checks.
3. **Static Analysis**: Investigating the malware’s structure without execution.
4. **Dynamic Analysis**: Executing the malware in a controlled sandbox to monitor behavior.
5. **IOC Collection**: Compiling key indicators for detection and threat hunting.
6. **Reporting**: Documenting findings and recommendations in a clear, actionable format.

---

# Malware Analysis Report: Skotes.exe

## 1. Objective

The goal of this analysis is to determine the functionality, behavior, and potential impact of the malware sample skotes.exe. The analysis will identify Indicators of Compromise (IOCs) and provide recommendations for detection and mitigation.

## 2. Sample Overview
- **Malwere**: Amadey
- **Threat Type**: Downloader
- **SHA256 hash**:	`4ff54307625cf4128e1f1d2ed924326e609b3f4dd14643717c27b196abcd1ea6`
- **File Type**: `Executable`
- **File Size**: `1.8 MB`
- **Source**: MalwareBazaar
  
![Screenshot 2024-11-29 at 3 13 01 PM](https://github.com/user-attachments/assets/3dfa0460-d43b-4a73-96ce-ba43e8310223)
![Screenshot 2024-11-29 at 3 14 43 PM](https://github.com/user-attachments/assets/8ff746ba-1531-4c3d-b8e1-11c701cdf889)

---
## 3. Static Analysis
### Metadata
- PE Header Information: Intel 386 or later and compatitble processors 
  - Timestamp: 2024-09-22 17:40:44 UTC
  - File Type: PE32 executable (GUI) Intel 80386, for MS Windows
  - Compressed: true
  - Entry Point: 0x4aa000
  - Signature: 17744
  - Suspicious Imports: kernel32.dll (Core System library in Windows responsible for various low-level operations, such as: Memory management, File I/O operations,Process and thread management) Operates under the funtion name `Istrcpy` and does not resemble standard functions exported by kernel32.dll
  - Crop
![Screenshot 2024-11-29 at 4 06 20 PM](https://github.com/user-attachments/assets/79f682f1-1361-4179-889f-f4dfe524eb1a)
---
### Strings
- **Extracted Domains**:
![Screenshot 2024-11-29 at 4 42 48 PM](https://github.com/user-attachments/assets/c92e1125-25df-4993-ab84-87e88fc4f222)
![Screenshot 2024-11-29 at 4 43 37 PM](https://github.com/user-attachments/assets/313d7968-39cf-4efd-824d-49c21df80dda)
---
- **File Paths: file paths, kand registry keys**:
![Screenshot 2024-11-29 at 4 54 04 PM](https://github.com/user-attachments/assets/20307197-755c-4f84-9442-4697e7c355d5)
![Screenshot 2024-11-29 at 4 54 35 PM](https://github.com/user-attachments/assets/efba816b-ffd0-402d-9ad1-ae590441258d)
![Screenshot 2024-11-29 at 5 05 36 PM](https://github.com/user-attachments/assets/d037c43c-98a0-4db1-adfa-a75cc0bd15c3)
---
- **Commands: Command-line instructions or encoded strings.**
  
![Screenshot 2024-11-29 at 5 06 32 PM](https://github.com/user-attachments/assets/b1a8da84-8434-4699-bfeb-2ac14665a4a0)
![Screenshot 2024-11-29 at 5 08 42 PM](https://github.com/user-attachments/assets/c8f5ffe6-fd05-4c4e-8525-be0caf1fabee)


---

## 4. Dynamic Analysis
### Behavior Observed
- **Processes Created**: `[process.exe]`
![Screenshot 2024-12-01 at 12 51 13 AM](https://github.com/user-attachments/assets/c33419a5-12b3-4312-b117-d45a074aabd4)
![Screenshot 2024-12-01 at 12 51 57 AM](https://github.com/user-attachments/assets/35e500a0-49de-47db-959a-8e12ef83c2f8)
![Screenshot 2024-12-01 at 12 52 06 AM](https://github.com/user-attachments/assets/d37d9403-1314-4a14-af01-9daded48fa95)

- **File Modifications**: `[C:\Temp\malicious.dll]`
![Screenshot 2024-12-01 at 12 52 24 AM](https://github.com/user-attachments/assets/53a9c543-6e6c-477e-a931-d09e5c638118)

- **Network Traffic**: 
![Screenshot 2024-11-30 at 11 19 38 PM](https://github.com/user-attachments/assets/6c95603f-6c61-4c37-96fd-4e170324833c)
![Screenshot 2024-12-01 at 12 45 42 AM](https://github.com/user-attachments/assets/02e1ec19-e6f8-49f4-9b88-12172239b6a5)

---

### Dynamic Analysis Summery per Unpac.me 
<img width="784" alt="Screenshot 2024-11-30 at 9 36 59 PM" src="https://github.com/user-attachments/assets/843f677f-bcfb-4740-904d-b1350abb7e6b">
<img width="784" alt="Screenshot 2024-11-30 at 9 37 18 PM" src="https://github.com/user-attachments/assets/409fc86a-ee7e-4361-9182-af06193a5710">
<img width="784" alt="Screenshot 2024-11-30 at 9 37 37 PM" src="https://github.com/user-attachments/assets/88e7c773-181b-4908-942e-a138ce03cf26">
<img width="784" alt="Screenshot 2024-11-30 at 9 38 03 PM" src="https://github.com/user-attachments/assets/d3e825ce-1345-495d-86e5-847acb946eb3">
<img width="784" alt="Screenshot 2024-11-30 at 9 38 17 PM" src="https://github.com/user-attachments/assets/e236bb87-2b9a-4cb4-b870-aa72e115144a">
<img width="784" alt="Screenshot 2024-11-30 at 9 38 25 PM" src="https://github.com/user-attachments/assets/936a24ca-d2ff-47d1-9c80-fb0e722e648b">

### Indicators of Compromise
<img width="784" alt="Screenshot 2024-11-30 at 8 51 53 PM" src="https://github.com/user-attachments/assets/bcb2b6e2-9d36-4ce3-a512-29765705edd8">
<img width="784" alt="Screenshot 2024-11-30 at 8 52 36 PM" src="https://github.com/user-attachments/assets/b1ae135a-bae6-43d5-a727-806de8cf5bc3">

- **With these we can**:
  - Monitor global network environments
  - Detect potential malware instances
  - Identify if the same threat exists in other networks network endpoints
  - Potential file modification in C:\Temp\malicious.dll
  - Unusual process interactions
---

## Threat Actors 
- TA505 has been observed using Amadey in campaigns targeting financial institutions.
<img width="998" alt="Screenshot 2024-11-30 at 9 50 05 PM" src="https://github.com/user-attachments/assets/c4385089-b96d-419e-beab-cf8f8fec86b0">
<img width="998" alt="Screenshot 2024-11-30 at 9 51 13 PM" src="https://github.com/user-attachments/assets/8c27fb37-ad37-472c-8906-eb736db79cb3">
## Documented Campaingns
- TA505 utilizes Excel 4.0 macros to deliver Amadey, leveraging LOLBins (Living
Off the Land Binaries) and a new backdoor malware as part of their tactics

## 5. Recommendations
- Block associated IOCs.
- Deploy updated signatures to endpoint security solutions.

## 6. References
- VirusTotal Report: `https://www.virustotal.com/gui/file/4ff54307625cf4128e1f1d2ed924326e609b3f4dd14643717c27b196abcd1ea6`
- Unpac.me: `https://www.unpac.me/results/32ff6a5c-c68c-4f85-935e-825fcefabd04`
