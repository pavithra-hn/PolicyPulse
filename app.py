from flask import Flask, request, jsonify, render_template, send_from_directory
import json
import uuid
import re
import os
from datetime import datetime
from typing import Dict, List, Any
import spacy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from email.mime.text import MIMEText
import sqlite3
import threading
import time

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Global variables
nlp = None
policy_rules = {}
scan_results = {}
email_data = {}

class PolicyChecker:
    def __init__(self):
        self.rules = {}
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.load_rules()
        
    def load_rules(self):
        """Load policy rules from JSON file"""
        try:
            with open('policy_rules.json', 'r') as f:
                self.rules = json.load(f)
        except FileNotFoundError:
            # Create default rules if file doesn't exist
            self.rules = {
                "forbidden_terms": {
                    "rule_id": "FORBIDDEN_001",
                    "description": "Prohibited language detection",
                    "severity": "high",
                    "patterns": [
                        r"\b(?:confidential|classified|secret|proprietary)\b",
                        r"\b(?:insider|leak|breach|violation)\b",
                        r"\b(?:hack|exploit|vulnerability)\b"
                    ]
                },
                "pii_detection": {
                    "rule_id": "PII_001", 
                    "description": "Personal Identifiable Information",
                    "severity": "critical",
                    "patterns": [
                        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                        r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # Credit card
                        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
                        r"\b\d{3}[\s.-]?\d{3}[\s.-]?\d{4}\b"  # Phone
                    ]
                },
                "financial_terms": {
                    "rule_id": "FIN_001",
                    "description": "Financial compliance violations",
                    "severity": "medium",
                    "patterns": [
                        r"\b(?:insider trading|market manipulation|fraud)\b",
                        r"\b(?:bribe|kickback|money laundering)\b",
                        r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s*(?:million|billion)"
                    ]
                },
                "data_privacy": {
                    "rule_id": "PRIV_001",
                    "description": "Data privacy violations",
                    "severity": "high",
                    "patterns": [
                        r"\b(?:gdpr|hipaa|pci|compliance)\s+(?:violation|breach)\b",
                        r"\b(?:personal data|sensitive information)\s+(?:exposed|leaked)\b",
                        r"\b(?:unauthorized access|data breach|privacy violation)\b"
                    ]
                }
            }
            self.save_rules()
    
    def save_rules(self):
        """Save rules to JSON file"""
        with open('policy_rules.json', 'w') as f:
            json.dump(self.rules, f, indent=2)
    
    def scan_text(self, text: str, scan_id: str) -> Dict[str, Any]:
        """Scan text for policy violations"""
        violations = []
        sentences = self.split_into_sentences(text)
        
        for sentence_idx, sentence in enumerate(sentences):
            sentence_violations = self.check_sentence(sentence, sentence_idx)
            violations.extend(sentence_violations)
        
        # ML-based semantic analysis
        semantic_violations = self.semantic_analysis(text)
        violations.extend(semantic_violations)
        
        result = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "total_violations": len(violations),
            "violations": violations,
            "text": text,
            "sentences": sentences,
            "risk_score": self.calculate_risk_score(violations)
        }
        
        return result
    
    def split_into_sentences(self, text: str) -> List[str]:
        """Split text into sentences using spaCy"""
        global nlp
        if nlp is None:
            try:
                nlp = spacy.load("en_core_web_sm")
            except OSError:
                # Fallback to simple sentence splitting
                return [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]
        
        doc = nlp(text)
        return [sent.text.strip() for sent in doc.sents if sent.text.strip()]
    
    def check_sentence(self, sentence: str, sentence_idx: int) -> List[Dict[str, Any]]:
        """Check a single sentence against all rules"""
        violations = []
        
        for rule_name, rule_data in self.rules.items():
            for pattern in rule_data['patterns']:
                matches = re.finditer(pattern, sentence, re.IGNORECASE)
                for match in matches:
                    violations.append({
                        "rule_id": rule_data['rule_id'],
                        "rule_name": rule_name,
                        "description": rule_data['description'],
                        "severity": rule_data['severity'],
                        "sentence_index": sentence_idx,
                        "sentence": sentence,
                        "matched_text": match.group(),
                        "start_pos": match.start(),
                        "end_pos": match.end(),
                        "confidence": 0.9  # Rule-based matches have high confidence
                    })
        
        return violations
    
    def semantic_analysis(self, text: str) -> List[Dict[str, Any]]:
        """Perform semantic analysis using TF-IDF and similarity"""
        violations = []
        
        # Define suspicious semantic patterns
        suspicious_phrases = [
            "avoid compliance requirements",
            "circumvent regulations", 
            "hide from auditors",
            "off the books transaction",
            "under the table payment",
            "keep this confidential from legal",
            "destroy these documents",
            "delete email trail"
        ]
        
        try:
            sentences = self.split_into_sentences(text)
            if len(sentences) < 2:
                return violations
                
            # Vectorize text
            all_text = sentences + suspicious_phrases
            tfidf_matrix = self.vectorizer.fit_transform(all_text)
            
            # Calculate similarity between sentences and suspicious phrases
            sentence_vectors = tfidf_matrix[:len(sentences)]
            suspicious_vectors = tfidf_matrix[len(sentences):]
            
            similarities = cosine_similarity(sentence_vectors, suspicious_vectors)
            
            for sent_idx, sentence in enumerate(sentences):
                max_similarity = np.max(similarities[sent_idx])
                if max_similarity > 0.3:  # Threshold for similarity
                    best_match_idx = np.argmax(similarities[sent_idx])
                    violations.append({
                        "rule_id": "ML_001",
                        "rule_name": "semantic_analysis",
                        "description": "Potentially suspicious content detected via ML",
                        "severity": "medium",
                        "sentence_index": sent_idx,
                        "sentence": sentence,
                        "matched_text": sentence,
                        "start_pos": 0,
                        "end_pos": len(sentence),
                        "confidence": float(max_similarity),
                        "similar_to": suspicious_phrases[best_match_idx]
                    })
        except Exception as e:
            print(f"Semantic analysis error: {e}")
        
        return violations
    
    def calculate_risk_score(self, violations: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score based on violations"""
        if not violations:
            return 0.0
        
        severity_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2}
        total_score = sum(severity_weights.get(v['severity'], 0.2) * v['confidence'] 
                         for v in violations)
        
        return min(total_score / len(violations), 1.0)

# Initialize policy checker
policy_checker = PolicyChecker()

# Email mock data generator
def generate_mock_emails():
    """Generate mock email data"""
    mock_emails = [
        {
            "id": "email_001",
            "subject": "Q4 Financial Results - CONFIDENTIAL",
            "sender": "cfo@company.com", 
            "body": "Our Q4 results show $2.5 million in undisclosed transactions. Please keep this confidential until we can adjust the books. My SSN is 123-45-6789 for verification.",
            "timestamp": "2025-01-15T10:30:00Z"
        },
        {
            "id": "email_002", 
            "subject": "Customer Data Export",
            "sender": "data@company.com",
            "body": "Attached is the customer database with credit card numbers 4532-1234-5678-9012 and personal information. Email me at john.doe@company.com if you need access.",
            "timestamp": "2025-01-14T14:20:00Z"
        },
        {
            "id": "email_003",
            "subject": "Compliance Training Reminder", 
            "sender": "hr@company.com",
            "body": "Please complete your annual compliance training by Friday. This covers GDPR, data privacy, and insider trading policies.",
            "timestamp": "2025-01-13T09:15:00Z"
        },
        {
            "id": "email_004",
            "subject": "Audit Preparation",
            "sender": "legal@company.com", 
            "body": "We need to avoid compliance requirements for the upcoming audit. Let's circumvent regulations where possible and hide sensitive documents from auditors.",
            "timestamp": "2025-01-12T16:45:00Z"
        }
    ]
    return {f"inbox_{i}": mock_emails for i in range(1, 4)}

email_data = generate_mock_emails()

@app.route('/')
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/scan', methods=['POST'])
def scan_document():
    """Scan document or text for policy violations"""
    data = request.get_json()
    
    if not data or 'text' not in data:
        return jsonify({"error": "Text content required"}), 400
    
    scan_id = str(uuid.uuid4())
    text = data['text']
    
    # Perform scan
    result = policy_checker.scan_text(text, scan_id)
    scan_results[scan_id] = result
    
    # Auto-fetch emails if requested
    if data.get('include_emails'):
        inbox_id = data.get('inbox_id', 'inbox_1')
        if inbox_id in email_data:
            email_text = "\n\n".join([
                f"Subject: {email['subject']}\nFrom: {email['sender']}\nBody: {email['body']}"
                for email in email_data[inbox_id]
            ])
            email_result = policy_checker.scan_text(email_text, f"{scan_id}_emails")
            result['email_scan'] = email_result
    
    return jsonify({
        "scan_id": scan_id,
        "status": "completed",
        "violations_found": result['total_violations'],
        "risk_score": result['risk_score']
    })

@app.route('/api/emails/<inbox_id>')
def get_emails(inbox_id):
    """Get mock emails from specified inbox"""
    if inbox_id not in email_data:
        return jsonify({"error": "Inbox not found"}), 404
    
    return jsonify({
        "inbox_id": inbox_id,
        "emails": email_data[inbox_id]
    })

@app.route('/api/reports/<scan_id>')
def get_report(scan_id):
    """Get detailed scan report"""
    if scan_id not in scan_results:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/rules')
def get_rules():
    """Get current policy rules"""
    return jsonify(policy_checker.rules)

@app.route('/api/rules', methods=['POST'])
def update_rules():
    """Update policy rules"""
    try:
        new_rules = request.get_json()
        policy_checker.rules = new_rules
        policy_checker.save_rules()
        return jsonify({"status": "Rules updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/scans')
def list_scans():
    """List all scan results"""
    scans = []
    for scan_id, result in scan_results.items():
        scans.append({
            "scan_id": scan_id,
            "timestamp": result['timestamp'],
            "violations": result['total_violations'],
            "risk_score": result['risk_score']
        })
    
    return jsonify({"scans": sorted(scans, key=lambda x: x['timestamp'], reverse=True)})

if __name__ == '__main__':
    # Create templates directory and files
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    print("Starting PolicyPulse server...")
    print("Dashboard available at: http://localhost:5000")
    print("API endpoints:")
    print("  POST /api/scan - Scan text for violations")
    print("  GET /api/reports/{scan_id} - Get scan report")
    print("  GET /api/emails/{inbox_id} - Get mock emails")
    print("  GET /api/rules - View policy rules")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
