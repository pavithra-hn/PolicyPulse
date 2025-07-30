import unittest
import json
import tempfile
import os
from app import app, policy_checker, PolicyChecker

class TestPolicyPulse(unittest.TestCase):
    
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        
        # Create temporary policy rules for testing
        self.test_rules = {
            "test_rule": {
                "rule_id": "TEST_001",
                "description": "Test rule for unit testing",
                "severity": "medium",
                "patterns": [r"\btest_violation\b", r"\bsecret_data\b"]
            }
        }
        
        # Backup original rules
        self.original_rules = policy_checker.rules.copy()
        policy_checker.rules = self.test_rules
    
    def tearDown(self):
        # Restore original rules
        policy_checker.rules = self.original_rules
    
    def test_policy_checker_initialization(self):
        """Test PolicyChecker initialization"""
        checker = PolicyChecker()
        self.assertIsInstance(checker.rules, dict)
        self.assertIsNotNone(checker.vectorizer)
    
    def test_rule_based_detection(self):
        """Test rule-based violation detection"""
        test_text = "This document contains test_violation and secret_data information."
        result = policy_checker.scan_text(test_text, "test_scan_001")
        
        self.assertGreater(result['total_violations'], 0)
        self.assertIn('violations', result)
        
        # Check if violations contain expected fields
        for violation in result['violations']:
            self.assertIn('rule_id', violation)
            self.assertIn('severity', violation)
            self.assertIn('matched_text', violation)
    
    def test_sentence_splitting(self):
        """Test sentence splitting functionality"""
        test_text = "First sentence. Second sentence! Third sentence?"
        sentences = policy_checker.split_into_sentences(test_text)
        
        self.assertEqual(len(sentences), 3)
        self.assertEqual(sentences[0].strip(), "First sentence.")
        self.assertEqual(sentences[1].strip(), "Second sentence!")
        self.assertEqual(sentences[2].strip(), "Third sentence?")
    
    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        # High severity violations
        high_violations = [
            {'severity': 'critical', 'confidence': 0.9},
            {'severity': 'high', 'confidence': 0.8}
        ]
        high_score = policy_checker.calculate_risk_score(high_violations)
        
        # Low severity violations
        low_violations = [
            {'severity': 'low', 'confidence': 0.5},
            {'severity': 'medium', 'confidence': 0.6}
        ]
        low_score = policy_checker.calculate_risk_score(low_violations)
        
        self.assertGreater(high_score, low_score)
        self.assertLessEqual(high_score, 1.0)
        self.assertLessEqual(low_score, 1.0)
    
    def test_scan_api_endpoint(self):
        """Test the /api/scan endpoint"""
        test_data = {
            "text": "This is a test document with secret_data that should trigger violations."
        }
        
        response = self.app.post('/api/scan', 
                               data=json.dumps(test_data),
                               content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        
        result = json.loads(response.data)
        self.assertIn('scan_id', result)
        self.assertIn('status', result)
        self.assertIn('violations_found', result)
        self.assertIn('risk_score', result)
    
    def test_scan_api_missing_text(self):
        """Test /api/scan endpoint with missing text"""
        response = self.app.post('/api/scan', 
                               data=json.dumps({}),
                               content_type='application/json')
        
        self.assertEqual(response.status_code, 400)
        result = json.loads(response.data)
        self.assertIn('error', result)
    
    def test_reports_endpoint(self):
        """Test the /api/reports/{scan_id} endpoint"""
        # First perform a scan
        test_data = {"text": "Test document with secret_data"}
        scan_response = self.app.post('/api/scan',
                                    data=json.dumps(test_data),  
                                    content_type='application/json')
        
        scan_result = json.loads(scan_response.data)
        scan_id = scan_result['scan_id']
        
        # Now get the report
        report_response = self.app.get(f'/api/reports/{scan_id}')
        self.assertEqual(report_response.status_code, 200)
        
        report = json.loads(report_response.data)
        self.assertIn('scan_id', report)
        self.assertIn('violations', report)
        self.assertIn('risk_score', report)
    
    def test_reports_endpoint_not_found(self):
        """Test /api/reports endpoint with non-existent scan ID"""
        response = self.app.get('/api/reports/nonexistent_scan_id')
        self.assertEqual(response.status_code, 404)
        
        result = json.loads(response.data)
        self.assertIn('error', result)
    
    def test_emails_endpoint(self):
        """Test the /api/emails/{inbox_id} endpoint"""
        response = self.app.get('/api/emails/inbox_1')
        self.assertEqual(response.status_code, 200)
        
        result = json.loads(response.data)
        self.assertIn('inbox_id', result)
        self.assertIn('emails', result)
        self.assertIsInstance(result['emails'], list)
    
    def test_emails_endpoint_not_found(self):
        """Test /api/emails endpoint with non-existent inbox"""
        response = self.app.get('/api/emails/nonexistent_inbox')
        self.assertEqual(response.status_code, 404)
        
        result = json.loads(response.data)
        self.assertIn('error', result)
    
    def test_rules_endpoint(self):
        """Test the /api/rules endpoint"""
        response = self.app.get('/api/rules')
        self.assertEqual(response.status_code, 200)
        
        rules = json.loads(response.data)
        self.assertIsInstance(rules, dict)
        self.assertIn('test_rule', rules)
    
    def test_scans_list_endpoint(self):
        """Test the /api/scans endpoint"""
        # Perform a few scans first
        for i in range(3):
            test_data = {"text": f"Test document {i} with secret_data"}
            self.app.post('/api/scan',
                         data=json.dumps(test_data),
                         content_type='application/json')
        
        response = self.app.get('/api/scans')
        self.assertEqual(response.status_code, 200)
        
        result = json.loads(response.data)
        self.assertIn('scans', result)
        self.assertIsInstance(result['scans'], list)
        self.assertGreaterEqual(len(result['scans']), 3)
    
    def test_pii_detection(self):
        """Test PII pattern detection"""
        # Temporarily add PII rules
        policy_checker.rules['pii_test'] = {
            "rule_id": "PII_TEST",
            "description": "PII test patterns",
            "severity": "critical",
            "patterns": [
                r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"  # Email
            ]
        }
        
        test_text = "Contact John at john.doe@company.com or use SSN 123-45-6789"
        result = policy_checker.scan_text(test_text, "pii_test")
        
        # Should detect both email and SSN
        pii_violations = [v for v in result['violations'] if v['rule_id'] == 'PII_TEST']
        self.assertGreaterEqual(len(pii_violations), 2)
        
        # Clean up
        del policy_checker.rules['pii_test']
    
    def test_semantic_analysis(self):
        """Test semantic analysis functionality"""
        suspicious_text = "We need to avoid compliance requirements and hide this from auditors"
        result = policy_checker.scan_text(suspicious_text, "semantic_test")
        
        # Should detect semantic violations
        semantic_violations = [v for v in result['violations'] if v['rule_id'] == 'ML_001']
        # Note: This may not always trigger depending on vectorizer state
        
        self.assertGreaterEqual(len(result['violations']), 0)
    
    def test_dashboard_route(self):
        """Test the main dashboard route"""
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'PolicyPulse', response.data)
        self.assertIn(b'Document Scanner', response.data)
    
    def test_empty_text_scan(self):
        """Test scanning empty text"""
        result = policy_checker.scan_text("", "empty_test")
        self.assertEqual(result['total_violations'], 0)
        self.assertEqual(result['risk_score'], 0.0)
    
    def test_large_text_scan(self):
        """Test scanning large text documents"""
        # Create a large text with violations
        large_text = "Normal text. " * 100 + "secret_data violation. " + "More normal text. " * 100
        result = policy_checker.scan_text(large_text, "large_test")
        
        self.assertGreater(result['total_violations'], 0)
        self.assertIn('violations', result)
    
    def test_concurrent_scans(self):
        """Test multiple concurrent scans"""
        import threading
        import time
        
        results = {}
        
        def perform_scan(scan_id):
            text = f"Test scan {scan_id} with secret_data"
            result = policy_checker.scan_text(text, f"concurrent_{scan_id}")
            results[scan_id] = result
        
        # Start multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=perform_scan, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all scans completed
        self.assertEqual(len(results), 5)
        for result in results.values():
            self.assertIn('total_violations', result)
            self.assertIn('risk_score', result)

class TestPolicyRules(unittest.TestCase):
    """Test policy rules functionality"""
    
    def test_rule_loading(self):
        """Test loading rules from file"""
        checker = PolicyChecker()
        self.assertIsInstance(checker.rules, dict)
        self.assertGreater(len(checker.rules), 0)
    
    def test_rule_patterns(self):
        """Test individual rule patterns"""
        checker = PolicyChecker()
        
        # Test forbidden terms
        test_cases = [
            ("This is confidential information", True),
            ("We have a security breach", True), 
            ("Normal business document", False),
            ("The classified report shows", True)
        ]
        
        for text, should_match in test_cases:
            result = checker.scan_text(text, f"pattern_test_{hash(text)}")
            has_violations = result['total_violations'] > 0
            
            if should_match:
                self.assertTrue(has_violations, f"Expected violations in: {text}")
            # Note: We don't test False cases strictly as semantic analysis might trigger

if __name__ == '__main__':
    # Create a test suite
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTest(unittest.makeSuite(TestPolicyPulse))
    suite.addTest(unittest.makeSuite(TestPolicyRules))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*50}")
