import unittest
from unittest.mock import Mock, patch
import socket
import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from rslvrDns import *
from constsDns import DnsType, DnsClass, DnsFlags, DnsRcode
from utilDns import DnsMessage, buildQ, buildResp

class TestDNSResolver(unittest.TestCase):
    def setUp(self):
        # Create a mock socket for testing
        self.mock_sock = Mock(spec=socket.socket)
        self.client_address = ('127.0.0.1', 12345)

    def test_noerror_response(self):
        """Test successful DNS query with NOERROR response"""
        # Create a test query for an existing domain
        query = buildQ('hahalol.com', 'A')
        query_wire = query.to_wire()
        
        # Handle the query
        handle_client(query_wire, self.client_address, self.mock_sock)
        
        # Check that sendto was called
        self.mock_sock.sendto.assert_called_once()
        
        # Get the response wire format
        response_wire = self.mock_sock.sendto.call_args[0][0]
        response = convertRaw_msg(response_wire)
        
        # Check RCODE is NOERROR (0)
        self.assertEqual(response.flags & 0x000F, DnsRcode.NOERROR)
        # Check response has answer
        self.assertTrue(len(response.answer) > 0)

 
    def test_format_error_response(self):
        """Test malformed query returns FORMERR"""
        # Create an invalid DNS message with valid ID but malformed question
        invalid_query = (
            b'\x00\x01'  # ID
            b'\x00\x00'  # Flags
            b'\x00\x01'  # QDCOUNT
            b'\x00\x00'  # ANCOUNT
            b'\x00\x00'  # NSCOUNT
            b'\x00\x00'  # ARCOUNT
            b'\x03'      # Invalid length byte without domain name
        )
        
        # Handle the query
        handle_client(invalid_query, self.client_address, self.mock_sock)
        
        # Get the response wire format
        response_wire = self.mock_sock.sendto.call_args[0][0]
        response = convertRaw_msg(response_wire)
        
        # Check RCODE is FORMERR (1)
        self.assertEqual(response.flags & 0x000F, DnsRcode.FORMERR)

    @patch('rslvrDns.recursive_dns_lookup')
    def test_server_failure_response(self, mock_recursive_lookup):
        """Test server failure during recursive lookup returns SERVFAIL"""
        # Make recursive_dns_lookup raise an exception
        mock_recursive_lookup.side_effect = Exception("Simulated server error")
        
        # Create a test query
        query = buildQ('example.com', 'A')
        query_wire = query.to_wire()
        
        # Handle the query
        handle_client(query_wire, self.client_address, self.mock_sock)
        
        # Get the response wire format
        response_wire = self.mock_sock.sendto.call_args[0][0]
        response = convertRaw_msg(response_wire)
        
        # Check RCODE is SERVFAIL (2)
        self.assertEqual(response.flags & 0x000F, DnsRcode.SERVFAIL)

    def test_response_flags(self):
        """Test response flags are set correctly"""
        # Create a test query for an existing domain
        query = buildQ('hahalol.com', 'A')
        query_wire = query.to_wire()
        
        # Handle the query
        handle_client(query_wire, self.client_address, self.mock_sock)
        
        # Get the response wire format
        response_wire = self.mock_sock.sendto.call_args[0][0]
        response = convertRaw_msg(response_wire)
        
        # Check QR flag is set (response)
        self.assertTrue(response.flags & DnsFlags.QR)
        # Check RA flag is set (recursion available)
        self.assertTrue(response.flags & DnsFlags.RA)
        # Check AA flag is set for authoritative answer
        self.assertTrue(response.flags & DnsFlags.AA)

if __name__ == '__main__':
    unittest.main()
