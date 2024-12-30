"""
DNS Server Configuration
"""

# Server Configuration
SERVER_IP = '127.0.0.66'
SERVER_PORT = 53
SOCKET_TIMEOUT = 2
MAX_PACKET_SIZE = 512
MAX_REFERRALS = 10

# DNS Configuration
TTL = 300  # Time to live for DNS records

ROOT_SERVERS = [
    # a.root-servers.net
    '198.41.0.4',    
    # b.root-servers.net
    '170.247.170.2',  
    # c.root-servers.net
    '192.33.4.12',   
    # d.root-servers.net
    '199.7.91.13',    
    # e.root-servers.net
    '192.203.230.10', 
    # f.root-servers.net
    '192.5.5.241',    
    # g.root-servers.net
    '192.112.36.4',   
    # h.root-servers.net
    '198.97.190.53',  
    # i.root-servers.net
    '192.36.148.17',  
    # j.root-servers.net
    '192.58.128.30',  
    # k.root-servers.net
    '193.0.14.129',   
    # l.root-servers.net
    '199.7.83.42',    
    #m.root-servers.net
    '202.12.27.33',   
]

# Local DNS Records with support for multiple record types
LOCAL_RECORDS = {
    'hahalol.com.': {
        'A': ['222.222.222.222'],
        'NS': ['ns1.hahalol.com.', 'ns2.hahalol.com.'],
        'MX': [(10, 'mail.hahalol.com.')],  # (preference, mail server)
        'CNAME': ['wer.hahalol.com.'],
        'PTR': []
    },
    'test123.com.': {
        'A': ['123.123.123.123'],
        'NS': ['ns1.test123.com.', 'ns2.test123.com.'],
        'MX': [(10, 'mail.test123.com.')],
        'CNAME': [],
        'PTR': []
    },
    'ns1.hahalol.com.': {
        'A': ['222.222.222.10'],
        'NS': [],
        'MX': [],
        'CNAME': [],
        'PTR': []
    },
    'ns2.hahalol.com.': {
        'A': ['222.222.222.11'],
        'NS': [],
        'MX': [],
        'CNAME': [],
        'PTR': []
    },
    'mail.hahalol.com.': {
        'A': ['222.222.222.20'],
        'NS': [],
        'MX': [],
        'CNAME': [],
        'PTR': []
    },
    'ns1.test123.com.': {
        'A': ['123.123.123.10'],
        'NS': [],
        'MX': [],
        'CNAME': [],
        'PTR': []
    },
    'ns2.test123.com.': {
        'A': ['123.123.123.11'],
        'NS': [],
        'MX': [],
        'CNAME': [],
        'PTR': []
    },
    'mail.test123.com.': {
        'A': ['123.123.123.20'],
        'NS': [],
        'MX': [],
        'CNAME': [],
        'PTR': []
    },
    'www.hahalol.com.': {
        'A': [],
        'NS': [],
        'MX': [],
        'CNAME': ['hahalol.com.'],
        'PTR': []
    },
    # PTR records for reverse DNS
    '222.222.222.222.in-addr.arpa.': {
        'A': [],
        'NS': [],
        'MX': [],
        'CNAME': [],
        'PTR': ['hahalol.com.']
    },
    '123.123.123.123.in-addr.arpa.': {
        'A': [],
        'NS': [],
        'MX': [],
        'CNAME': [],
        'PTR': ['test123.com.']
    }
}

# Logging Configuration
LOG_FILE = 'logs.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'DEBUG'