from test_base import DNSTestCase
import dns.message
import dns.rdatatype
import dns.rcode

import sys
import os
# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from dnsServer import process_query  # Import your query processing function

class TestDNSMessageHandling(DNSTestCase):
    def test_nxdomain_handling(self):
        """Test NXDOMAIN response for non-existent domains"""
        query = dns.message.make_query(
            'nonexistent.example', 
            dns.rdatatype.A
        )
        
        response = dns.query.udp(
            query,
            self.server_addr,
            port=self.server_port,
            timeout=self.timeout
        )
        
        self.assertEqual(response.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(len(response.answer), 0)

    def test_malformed_query(self):
        """Test handling of malformed queries"""
        # Create an intentionally malformed query
        query = dns.message.make_query('example.com', dns.rdatatype.A)
        wire = query.to_wire()[:-2]  # Truncate the message
        
        try:
            response = dns.query.udp_with_fallback(
                wire,
                self.server_addr,
                port=self.server_port,
                timeout=self.timeout
            )
            self.assertEqual(response.rcode(), dns.rcode.FORMERR)
        except dns.exception.FormError:
            # This is also acceptable - server might reject malformed queries
            pass