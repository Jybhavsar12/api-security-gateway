#!/usr/bin/env python3
"""
API Security Gateway Test Suite
Comprehensive testing for security features
"""

import requests
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor

class GatewayTester:
    def __init__(self, gateway_url="http://localhost:8000", api_key="demo-key-12345"):
        self.gateway_url = gateway_url
        self.api_key = api_key
        self.results = []
    
    def log_result(self, test_name, passed, details=""):
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"    {details}")
        self.results.append({
            'test': test_name,
            'passed': passed,
            'details': details
        })
    
    def test_basic_connectivity(self):
        """Test basic gateway connectivity"""
        try:
            response = requests.get(f"{self.gateway_url}/", timeout=5)
            self.log_result("Basic Connectivity", True, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result("Basic Connectivity", False, str(e))
    
    def test_api_key_auth(self):
        """Test API key authentication"""
        # Test without API key
        try:
            response = requests.get(f"{self.gateway_url}/test", timeout=5)
            no_key_blocked = response.status_code == 401
        except:
            no_key_blocked = False
        
        # Test with valid API key
        try:
            headers = {"X-API-Key": self.api_key}
            response = requests.get(f"{self.gateway_url}/test", headers=headers, timeout=5)
            with_key_works = response.status_code != 401
        except:
            with_key_works = False
        
        passed = no_key_blocked and with_key_works
        details = f"No key: {no_key_blocked}, With key: {with_key_works}"
        self.log_result("API Key Authentication", passed, details)
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        headers = {"X-API-Key": self.api_key}
        
        # Send rapid requests
        responses = []
        for i in range(60):  # Send 60 requests rapidly
            try:
                response = requests.get(f"{self.gateway_url}/test", headers=headers, timeout=1)
                responses.append(response.status_code)
            except:
                responses.append(0)
        
        # Check if any requests were rate limited (429)
        rate_limited = 429 in responses
        self.log_result("Rate Limiting", rate_limited, f"Rate limited responses: {responses.count(429)}")
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        headers = {"X-API-Key": self.api_key}
        
        sql_payloads = [
            "' UNION SELECT * FROM users--",
            "1; DROP TABLE users;--",
            "' OR '1'='1",
            "admin'--",
            "1' OR 1=1#"
        ]
        
        blocked_count = 0
        for payload in sql_payloads:
            try:
                response = requests.get(
                    f"{self.gateway_url}/search",
                    params={"q": payload},
                    headers=headers,
                    timeout=5
                )
                if response.status_code in [400, 403]:
                    blocked_count += 1
            except:
                pass
        
        passed = blocked_count > 0
        self.log_result("SQL Injection Detection", passed, f"Blocked {blocked_count}/{len(sql_payloads)} payloads")
    
    def test_xss_detection(self):
        """Test XSS detection"""
        headers = {"X-API-Key": self.api_key}
        
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg onload=alert('xss')>",
            "eval('alert(1)')"
        ]
        
        blocked_count = 0
        for payload in xss_payloads:
            try:
                response = requests.get(
                    f"{self.gateway_url}/comment",
                    params={"text": payload},
                    headers=headers,
                    timeout=5
                )
                if response.status_code in [400, 403]:
                    blocked_count += 1
            except:
                pass
        
        passed = blocked_count > 0
        self.log_result("XSS Detection", passed, f"Blocked {blocked_count}/{len(xss_payloads)} payloads")
    
    def test_path_traversal_detection(self):
        """Test path traversal detection"""
        headers = {"X-API-Key": self.api_key}
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "/proc/version"
        ]
        
        blocked_count = 0
        for payload in traversal_payloads:
            try:
                response = requests.get(
                    f"{self.gateway_url}/file",
                    params={"path": payload},
                    headers=headers,
                    timeout=5
                )
                if response.status_code in [400, 403]:
                    blocked_count += 1
            except:
                pass
        
        passed = blocked_count > 0
        self.log_result("Path Traversal Detection", passed, f"Blocked {blocked_count}/{len(traversal_payloads)} payloads")
    
    def test_command_injection_detection(self):
        """Test command injection detection"""
        headers = {"X-API-Key": self.api_key}
        
        command_payloads = [
            "; cat /etc/passwd",
            "| nc -l 4444",
            "`whoami`",
            "$(id)",
            "&& cat /etc/shadow"
        ]
        
        blocked_count = 0
        for payload in command_payloads:
            try:
                response = requests.get(
                    f"{self.gateway_url}/exec",
                    params={"cmd": payload},
                    headers=headers,
                    timeout=5
                )
                if response.status_code in [400, 403]:
                    blocked_count += 1
            except:
                pass
        
        passed = blocked_count > 0
        self.log_result("Command Injection Detection", passed, f"Blocked {blocked_count}/{len(command_payloads)} payloads")
    
    def test_large_request_blocking(self):
        """Test large request blocking"""
        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        
        # Create a large payload (>10MB)
        large_data = {"data": "A" * (11 * 1024 * 1024)}  # 11MB
        
        try:
            response = requests.post(
                f"{self.gateway_url}/upload",
                json=large_data,
                headers=headers,
                timeout=10
            )
            blocked = response.status_code == 413
        except:
            blocked = False
        
        self.log_result("Large Request Blocking", blocked, f"Large request blocked: {blocked}")
    
    def test_cors_headers(self):
        """Test CORS headers"""
        headers = {"X-API-Key": self.api_key, "Origin": "https://example.com"}
        
        try:
            response = requests.options(f"{self.gateway_url}/api", headers=headers, timeout=5)
            has_cors = "Access-Control-Allow-Origin" in response.headers
        except:
            has_cors = False
        
        self.log_result("CORS Headers", has_cors, f"CORS headers present: {has_cors}")
    
    def test_security_headers(self):
        """Test security headers"""
        headers = {"X-API-Key": self.api_key}
        
        try:
            response = requests.get(f"{self.gateway_url}/", headers=headers, timeout=5)
            
            security_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security"
            ]
            
            present_headers = sum(1 for header in security_headers if header in response.headers)
            passed = present_headers >= 2  # At least 2 security headers
            
        except:
            passed = False
            present_headers = 0
        
        self.log_result("Security Headers", passed, f"{present_headers}/{len(security_headers)} headers present")
    
    def test_concurrent_requests(self):
        """Test handling of concurrent requests"""
        headers = {"X-API-Key": self.api_key}
        
        def make_request():
            try:
                response = requests.get(f"{self.gateway_url}/test", headers=headers, timeout=5)
                return response.status_code
            except:
                return 0
        
        # Send 20 concurrent requests
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(20)]
            results = [future.result() for future in futures]
        
        successful = sum(1 for code in results if 200 <= code < 400)
        passed = successful >= 15  # At least 75% success rate
        
        self.log_result("Concurrent Requests", passed, f"{successful}/20 requests successful")
    
    def run_all_tests(self):
        """Run all security tests"""
        print("🛡️  API Security Gateway Test Suite")
        print("=" * 50)
        
        tests = [
            self.test_basic_connectivity,
            self.test_api_key_auth,
            self.test_rate_limiting,
            self.test_sql_injection_detection,
            self.test_xss_detection,
            self.test_path_traversal_detection,
            self.test_command_injection_detection,
            self.test_large_request_blocking,
            self.test_cors_headers,
            self.test_security_headers,
            self.test_concurrent_requests
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                self.log_result(test.__name__, False, f"Test error: {e}")
            time.sleep(0.5)  # Brief pause between tests
        
        # Summary
        print("\n" + "=" * 50)
        passed_tests = sum(1 for result in self.results if result['passed'])
        total_tests = len(self.results)
        
        print(f"📊 Test Results: {passed_tests}/{total_tests} tests passed")
        
        if passed_tests == total_tests:
            print("🎉 All tests passed! Gateway is working correctly.")
        elif passed_tests >= total_tests * 0.8:
            print("⚠️  Most tests passed. Check failed tests above.")
        else:
            print("❌ Multiple tests failed. Gateway may have issues.")
        
        return passed_tests, total_tests

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='API Security Gateway Test Suite')
    parser.add_argument('--url', default='http://localhost:8000', help='Gateway URL')
    parser.add_argument('--api-key', default='demo-key-12345', help='API key for testing')
    parser.add_argument('--test', help='Run specific test')
    
    args = parser.parse_args()
    
    tester = GatewayTester(args.url, args.api_key)
    
    if args.test:
        # Run specific test
        test_method = getattr(tester, f"test_{args.test}", None)
        if test_method:
            test_method()
        else:
            print(f"Test '{args.test}' not found")
    else:
        # Run all tests
        tester.run_all_tests()

if __name__ == '__main__':
    main()