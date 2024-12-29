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
    '198.41.0.4',    # a.root-servers.net
    '199.9.14.201',  # b.root-servers.net
    '192.33.4.12',   # c.root-servers.net
]

# Local DNS Records
LOCAL_RECORDS = {
    'hahalol.com.': '222.222.222.222',
    'test123.com.': '123.123.123.123'
}

# Logging Configuration
LOG_FILE = 'logs.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'DEBUG'