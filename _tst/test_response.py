import unittest
import sys
import os
# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from dnsServer import *



class TestDnsResponseBuilding(unittest.TestCase):
    def test_build_basic_response(self):
        # Test building a basic A record response
        query_id = 1234
        response = buildResp(query_id)
        
        self.assertEqual(response.id, query_id)
        self.assertTrue(response.flags & DnsFlags.QR)  # Check if QR bit is set
        
    def test_build_a_record_answer(self):
        name = "example.com"
        ttl = 300
        ip = "93.184.216.34"
        
        answer = buildAns(name, ttl, DnsClass.IN, DnsType.A, ip)
        
        # Answer should start with compression pointer
        self.assertTrue(answer.startswith(b'\xc0\x0c'))