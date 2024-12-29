import unittest
import threading
import time

import sys
import os
# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from dnsServer import DnsServer  # Import your DNS server class

class DNSTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_addr = '127.0.0.1'
        cls.server_port = 5353
        cls.timeout = 3.0
        
        # Start DNS server in a separate thread
        cls.server = DnsServer(cls.server_addr, cls.server_port)
        cls.server_thread = threading.Thread(target=cls.server.start)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        
        # Wait for server to start
        time.sleep(1)
    
    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.server_thread.join(timeout=5)