

# 🛡️ PolicyPulse - Compliance Violation Detection System

**PolicyPulse** is an intelligent text-scanning tool designed to detect policy violations, suspicious patterns, and sensitive data disclosures in unstructured text or email content. It leverages a hybrid approach of **rule-based regex patterns** and **machine learning (TF-IDF + cosine similarity)** for robust policy compliance checks.

---

## 🚀 Features

* 🔍 Rule-based scanning using customizable regex patterns
* 🤖 Semantic analysis using TF-IDF + Cosine Similarity
* 🧠 NLP-powered sentence segmentation via spaCy
* 📩 Simulated email inbox with mock data scanning
* 🧾 API endpoints for scanning, reporting, and rule management
* 🌐 Web dashboard frontend (`dashboard.html`)

---

## 📁 Project Structure

```
policypulse/
│
├── app.py                 # Main Flask server with endpoints
├── policy_rules.json      # JSON-based rule definitions
├── templates/
│   └── dashboard.html     # Web dashboard template
├── static/                # Static assets (optional)
└── README.md              # You're here
```

---

## 🧠 How It Works

1. **Rule-Based Detection:** Uses regex patterns to identify forbidden terms, PII, financial, and privacy-related content.
2. **Semantic Analysis:** Flags semantically suspicious sentences based on similarity to known illicit patterns.
3. **Mock Email Scan:** Simulates email inbox scanning to detect leaks, compliance breaches, or sensitive disclosures.

---

## ⚙️ Installation

```bash
git clone https://github.com/pavithra-hn/policypulse.git
cd policypulse
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python app.py
```

Server starts at: [http://localhost:5000](http://localhost:5000)

---

## 🧪 API Endpoints

### 🔹 Scan Text

**POST** `/api/scan`

**Request JSON:**

```json
{
  "text": "Your text here...",
  "include_emails": true,
  "inbox_id": "inbox_1"
}
```

**Response:**

```json
{
  "scan_id": "...",
  "risk_score": 0.85,
  "violations_found": ["SSN detected", "Confidential phrase found"]
}
```

---

### 🔹 Get Scan Report

**GET** `/api/reports/<scan_id>`

---

### 🔹 Get Mock Emails

**GET** `/api/emails/<inbox_id>`

---

### 🔹 View or Update Policy Rules

**GET** `/api/rules`
**POST** `/api/rules`

---

### 🔹 List All Scans

**GET** `/api/scans`

---

## 📧 Example Email Violations

* Financial leaks
* SSN and Credit Card exposure
* Compliance avoidance statements
* Insider trading references

---

## 🧩 Technologies Used

* Python, Flask
* spaCy (NLP)
* scikit-learn (TF-IDF, Cosine Similarity)
* Regex, JSON
* SQLite (optional), threading
* HTML (Jinja2 for dashboard)

---

## 🛠 Future Enhancements

* Persistent database for scan history
* Frontend UI for managing scans and results
* Role-based access for compliance teams
* PDF/Docx document scanning support

---

## 📝 License

MIT License © 2025 \[Pavithra H N]

---

## 📬 Contact

For queries or contributions, feel free to reach out:
📧 **[pavithrahn56@gmail.com](mailto:pavithrahn56@gmail.com)**

---


