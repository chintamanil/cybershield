"""
Tests for regex checker tool
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools.regex_checker import RegexChecker, extract_iocs, validate_ip, validate_domain, validate_hash, analyze_url


class TestRegexChecker(unittest.TestCase):
    """Test cases for RegexChecker class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.checker = RegexChecker()
    
    def test_extract_ipv4_addresses(self):
        """Test IPv4 address extraction"""
        text = "Connect to 192.168.1.1 and 8.8.8.8 but not 999.999.999.999"
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('ipv4', result)
        self.assertEqual(len(result['ipv4']), 2)
        self.assertIn('192.168.1.1', result['ipv4'])
        self.assertIn('8.8.8.8', result['ipv4'])
        self.assertNotIn('999.999.999.999', result['ipv4'])
    
    def test_extract_domains(self):
        """Test domain extraction"""
        text = "Visit google.com and malicious-site.tk for more info"
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('domain', result)
        self.assertIn('google.com', result['domain'])
        self.assertIn('malicious-site.tk', result['domain'])
        
        self.assertIn('suspicious_tld', result)
        self.assertIn('malicious-site.tk', result['suspicious_tld'])
    
    def test_extract_hashes(self):
        """Test hash extraction"""
        text = """
        MD5: 5d41402abc4b2a76b9719d911017c592
        SHA1: 356a192b7913b04c54574d18c28d46e6395428ab
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('md5', result)
        self.assertEqual(len(result['md5']), 1)
        
        self.assertIn('sha1', result)
        self.assertEqual(len(result['sha1']), 1)
        
        self.assertIn('sha256', result)
        self.assertEqual(len(result['sha256']), 1)
    
    def test_extract_emails(self):
        """Test email extraction"""
        text = "Contact admin@example.com or spam@tempmail.com"
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('email', result)
        self.assertEqual(len(result['email']), 2)
        
        self.assertIn('suspicious_email', result)
        self.assertIn('spam@tempmail.com', result['suspicious_email'])
    
    def test_extract_urls(self):
        """Test URL extraction"""
        text = "Visit https://example.com/path?param=value and http://malware.com"
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('url', result)
        self.assertEqual(len(result['url']), 2)
    
    def test_extract_file_types(self):
        """Test file type extraction"""
        text = "Download malware.exe, document.pdf, and archive.zip"
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('executable', result)
        self.assertIn('malware.exe', result['executable'])
        
        self.assertIn('document', result)
        self.assertIn('document.pdf', result['document'])
        
        self.assertIn('archive', result)
        self.assertIn('archive.zip', result['archive'])
    
    def test_extract_cryptocurrency_addresses(self):
        """Test cryptocurrency address extraction"""
        text = """
        Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Ethereum: 0x742d35Cc6634C0532925a3b8D1C9DDF2D5b8b32E
        """
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('bitcoin_address', result)
        self.assertEqual(len(result['bitcoin_address']), 1)
        
        self.assertIn('ethereum_address', result)
        self.assertEqual(len(result['ethereum_address']), 1)
    
    def test_extract_cve_references(self):
        """Test CVE reference extraction"""
        text = "Vulnerability CVE-2021-44228 and CVE-2022-1234567 found"
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('cve', result)
        self.assertEqual(len(result['cve']), 2)
        self.assertIn('CVE-2021-44228', result['cve'])
    
    def test_private_vs_public_ip_categorization(self):
        """Test private vs public IP categorization"""
        text = "Private: 192.168.1.1 10.0.0.1 Public: 8.8.8.8 1.1.1.1"
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('private_ipv4', result)
        self.assertIn('public_ipv4', result)
        
        self.assertEqual(len(result['private_ipv4']), 2)
        self.assertEqual(len(result['public_ipv4']), 2)


class TestIPValidation(unittest.TestCase):
    """Test cases for IP validation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.checker = RegexChecker()
    
    def test_valid_ipv4(self):
        """Test valid IPv4 validation"""
        result = self.checker.validate_ip("192.168.1.1")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['version'], 4)
        self.assertTrue(result['is_private'])
    
    def test_valid_ipv6(self):
        """Test valid IPv6 validation"""
        result = self.checker.validate_ip("2001:db8::1")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['version'], 6)
    
    def test_invalid_ip(self):
        """Test invalid IP validation"""
        result = self.checker.validate_ip("999.999.999.999")
        
        self.assertFalse(result['is_valid'])
        self.assertIn('error', result)
    
    def test_public_ip_characteristics(self):
        """Test public IP characteristics"""
        result = self.checker.validate_ip("8.8.8.8")
        
        self.assertTrue(result['is_valid'])
        self.assertFalse(result['is_private'])
        self.assertFalse(result['is_loopback'])
        self.assertFalse(result['is_multicast'])


class TestDomainValidation(unittest.TestCase):
    """Test cases for domain validation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.checker = RegexChecker()
    
    def test_valid_domain(self):
        """Test valid domain validation"""
        result = self.checker.validate_domain("example.com")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['tld'], 'com')
        self.assertFalse(result['is_suspicious_tld'])
    
    def test_suspicious_tld(self):
        """Test suspicious TLD detection"""
        result = self.checker.validate_domain("malware.tk")
        
        self.assertTrue(result['is_valid'])
        self.assertTrue(result['is_suspicious_tld'])
        self.assertEqual(result['tld'], 'tk')
    
    def test_subdomain_counting(self):
        """Test subdomain counting"""
        result = self.checker.validate_domain("sub.example.com")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['subdomain_count'], 1)
    
    def test_invalid_domain(self):
        """Test invalid domain format"""
        result = self.checker.validate_domain("invalid..domain")
        
        self.assertFalse(result['is_valid'])


class TestHashValidation(unittest.TestCase):
    """Test cases for hash validation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.checker = RegexChecker()
    
    def test_md5_hash(self):
        """Test MD5 hash validation"""
        result = self.checker.validate_hash("5d41402abc4b2a76b9719d911017c592")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['type'], 'MD5')
        self.assertEqual(result['length'], 32)
    
    def test_sha1_hash(self):
        """Test SHA1 hash validation"""
        result = self.checker.validate_hash("356a192b7913b04c54574d18c28d46e6395428ab")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['type'], 'SHA1')
        self.assertEqual(result['length'], 40)
    
    def test_sha256_hash(self):
        """Test SHA256 hash validation"""
        result = self.checker.validate_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['type'], 'SHA256')
        self.assertEqual(result['length'], 64)
    
    def test_invalid_hash(self):
        """Test invalid hash format"""
        result = self.checker.validate_hash("invalid_hash")
        
        self.assertFalse(result['is_valid'])
        self.assertIn('error', result)
    
    def test_hex_prefix_removal(self):
        """Test hex prefix removal"""
        result = self.checker.validate_hash("0x5d41402abc4b2a76b9719d911017c592")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['type'], 'MD5')


class TestURLAnalysis(unittest.TestCase):
    """Test cases for URL analysis"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.checker = RegexChecker()
    
    def test_normal_url(self):
        """Test normal URL analysis"""
        result = self.checker.analyze_url("https://example.com/path")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['scheme'], 'https')
        self.assertEqual(result['domain'], 'example.com')
        self.assertEqual(result['path'], '/path')
        self.assertEqual(result['risk_score'], 0)
    
    def test_suspicious_url_characteristics(self):
        """Test suspicious URL detection"""
        long_url = "http://192.168.1.1/" + "a" * 200
        result = self.checker.analyze_url(long_url)
        
        self.assertTrue(result['is_valid'])
        self.assertGreater(result['risk_score'], 0)
        self.assertIn("IP address instead of domain", result['suspicious_indicators'])
        self.assertIn("Unusually long URL", result['suspicious_indicators'])
    
    def test_unusual_scheme(self):
        """Test unusual scheme detection"""
        result = self.checker.analyze_url("ftp://example.com/file")
        
        self.assertTrue(result['is_valid'])
        self.assertGreater(result['risk_score'], 0)
        self.assertIn("Unusual scheme: ftp", result['suspicious_indicators'])
    
    def test_invalid_url(self):
        """Test invalid URL handling"""
        result = self.checker.analyze_url("not_a_url")
        
        self.assertFalse(result['is_valid'])
        self.assertIn('error', result)


class TestConvenienceFunctions(unittest.TestCase):
    """Test cases for convenience functions"""
    
    def test_extract_iocs_function(self):
        """Test extract_iocs convenience function"""
        text = "Visit 192.168.1.1 and google.com"
        result = extract_iocs(text)
        
        self.assertIsInstance(result, dict)
        self.assertIn('ipv4', result)
        self.assertIn('domain', result)
    
    def test_validate_ip_function(self):
        """Test validate_ip convenience function"""
        result = validate_ip("8.8.8.8")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['version'], 4)
    
    def test_validate_domain_function(self):
        """Test validate_domain convenience function"""
        result = validate_domain("example.com")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['tld'], 'com')
    
    def test_validate_hash_function(self):
        """Test validate_hash convenience function"""
        result = validate_hash("5d41402abc4b2a76b9719d911017c592")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['type'], 'MD5')
    
    def test_analyze_url_function(self):
        """Test analyze_url convenience function"""
        result = analyze_url("https://example.com")
        
        self.assertTrue(result['is_valid'])
        self.assertEqual(result['scheme'], 'https')


class TestEdgeCases(unittest.TestCase):
    """Test cases for edge cases and error handling"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.checker = RegexChecker()
    
    def test_empty_text(self):
        """Test empty text handling"""
        result = self.checker.extract_all_iocs("")
        
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 0)
    
    def test_none_input(self):
        """Test None input handling"""
        with self.assertRaises(AttributeError):
            self.checker.extract_all_iocs(None)
    
    def test_duplicate_removal(self):
        """Test duplicate IOC removal"""
        text = "192.168.1.1 and 192.168.1.1 again"
        result = self.checker.extract_all_iocs(text)
        
        self.assertEqual(len(result['ipv4']), 1)
        self.assertEqual(result['ipv4'][0], '192.168.1.1')
    
    def test_case_insensitive_matching(self):
        """Test case insensitive matching"""
        text = "DOMAIN.COM and domain.com"
        result = self.checker.extract_all_iocs(text)
        
        self.assertIn('domain', result)
        # Should find both cases
        self.assertGreaterEqual(len(result['domain']), 1)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)