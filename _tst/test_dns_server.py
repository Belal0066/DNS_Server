import unittest
import dns.message
import dns.query
import dns.rdatatype
import dns.flags
import socket
import threading
import time
import sys
import os

# Add the src directory to the path so we can import the server
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from dnsServer import setup_server

class TestDNSServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_addr = '127.0.0.66'
        cls.server_port = 53
        cls.timeout = 3.0
        
        # Start DNS server in a separate thread
        cls.server_thread = threading.Thread(target=setup_server)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        
        # Wait for server to start
        time.sleep(1)

    def make_query(self, qname, rdtype=dns.rdatatype.A):
        """Helper method to create a DNS query"""
        query = dns.message.make_query(qname, rdtype)
        try:
            return dns.query.udp(
                query, 
                self.server_addr, 
                port=self.server_port, 
                timeout=self.timeout
            )
        except dns.exception.Timeout:
            self.fail(f"Query timed out for {qname}")

    def test_basic_query(self):
        """Test basic A record query"""
        response = self.make_query('hahalol.com')
        
        self.assertEqual(response.rcode(), dns.rcode.NOERROR)
        self.assertTrue(len(response.answer) > 0)
        self.assertEqual(str(response.answer[0][0]), '222.222.222.222')

    def test_recursive_resolution(self):
        """Test recursive resolution for external domains"""
        response = self.make_query('google.com')
        
        self.assertEqual(response.rcode(), dns.rcode.NOERROR)
        self.assertTrue(len(response.answer) > 0)
        self.assertFalse(response.flags & dns.flags.AA)

if __name__ == '__main__':
    unittest.main()