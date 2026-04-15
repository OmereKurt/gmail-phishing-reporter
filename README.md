# 🛡️ Gmail Phishing Reporting & Response Add-o

## 🔍 Overview
Gmail Phishing Reporter is a Google Workspace add-on that enables users to report phishing or suspicious emails directly within the Gmail interface.  

The tool focuses on streamlining user-driven incident response by automatically removing reported emails from the inbox and logging each event for audit and analysis.  

This project demonstrates how lightweight automation can reduce user exposure to malicious content while introducing real-world security workflows.

---

## 🚀 Features
- One-click phishing reporting from the Gmail sidebar  
- Confirmation step to prevent accidental actions  
- Automated response: removes reported emails from the inbox (moves to Trash)  
- Logging system using Google Sheets (timestamp, sender, subject, etc.)  
- Lightweight audit trail for tracking and reviewing reported emails  

---

## 🧠 Security Context
This project explores key incident response and security automation concepts, including:

- User-driven phishing reporting workflows  
- Automated response actions (removal/quarantine)  
- Event logging and audit trails  
- Reducing user exposure to phishing threats  

---

## ⚙️ Tech Stack
- Google Apps Script (JavaScript)  
- Gmail Add-on (Google Workspace)  
- Google Sheets (logging system)  

---

## 🧩 Repository Structure


---

## 💻 Setup & Installation
1. Create a new Apps Script project  
2. Replace `Code.gs` and `appsscript.json` with the provided files  
3. Configure your Google Sheet for logging  
4. Deploy as a Google Workspace Add-on  
5. Install the test deployment and authorize required permissions  
6. Open Gmail and test the add-on in the sidebar  

---

## 🔍 Workflow Example
1. User opens an email in Gmail  
2. Add-on appears in the sidebar  
3. User clicks **Report Phishing**  
4. Confirmation prompt is displayed  
5. Upon confirmation:
   - Email is removed from the inbox  
   - Event is logged in Google Sheets  

---

## 📊 Example Log Output
| Timestamp | Sender | Subject | Message ID | Thread ID | Action |
|----------|--------|--------|------------|-----------|--------|
| 2026-04-13 | test@example.com | Verify Account | ... | ... | Moved to Trash |

---

## 🔮 Future Enhancements
- Add undo/restore functionality for reported emails  
- Implement dashboard for report analytics  
- Add automated detection rules for suspicious emails  
- Expand logging with user attribution and categorization  

---

## 📄 License
This project is licensed under the MIT License.

---

## 👤 Author
**Omer Kurt**  
Cybersecurity student focused on incident response, threat detection, and security automation  
