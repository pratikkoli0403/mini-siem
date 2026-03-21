# Mini SIEM Log Analyzer

## 📌 Project Overview
This project is a **Mini SIEM (Security Information and Event Management) system** built using Python and Flask.

It analyzes authentication logs to detect suspicious login activities such as brute-force attacks.

---

## 🚀 Features

- Log file upload and analysis
- Detection of failed login attempts
- Risk-based severity classification (LOW / MEDIUM / HIGH)
- Web dashboard visualization (Chart.js)
- Demo attack simulation
- Downloadable security report
- CLI-based log analysis

---

## 🛠️ How to Run (Web Version)

### Step 1: Clone the repository
git clone https://github.com/pratikkoli0403/mini-siem.git
cd mini-siem

### Step 2: Create virtual environment
python3 -m venv venv
source venv/bin/activate
(Windows)venv\Scripts\activate


### Step 3: Install dependencies
pip install flask

### Step 4: Run the application
python web_app.py

Open browser:http://127.0.0.1:5000

---

## 💻 CLI Mode (Terminal)
python main.py

This runs log analysis directly in terminal.

---

## 🎯 Demo Options

### 1. Upload Log File
- Choose a log file and click **Analyze Logs**

### 2. Demo Attack Simulation
- Click **Generate Demo Attack**

### 3. Download Report
- Click **Download Security Report**

---

## 📊 Severity Logic

- LOW → Few failed attempts  
- MEDIUM → Moderate attempts  
- HIGH → Repeated brute-force attempts  

---

## 📦 Backup Run (ZIP)

If GitHub fails:

1. Extract ZIP
2. Run:

---

## Author

Pratik Koli
