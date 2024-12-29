#constsDns.py

ROOT_SERVERS = [
    '198.41.0.4',    # a.root-servers.net
    '199.9.14.201',  # b.root-servers.net
    '192.33.4.12',   # c.root-servers.net
    '199.7.91.13',   # d.root-servers.net
    '192.203.230.10' # e.root-servers.net
]

SERVER_PORT = 53


# DNS Record Types
class DnsType:
    A = 1       # Address record
    NS = 2      # Nameserver record
    CNAME = 5   # Canonical name record
    SOA = 6     # Start of authority record
    PTR = 12    # Pointer record
    MX = 15     # Mail exchange record
    TXT = 16    # Text record
    AAAA = 28   # IPv6 address record
    
    @staticmethod
    def to_text(rdtype):
        types = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
                12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
        return types.get(rdtype, f'TYPE{rdtype}')

# DNS Classes
class DnsClass:
    IN = 1      # Internet
    
    @staticmethod
    def to_text(rdclass):
        classes = {1: 'IN'}
        return classes.get(rdclass, f'CLASS{rdclass}')

# response Codes
class DnsRcode:
    NOERROR = 0x0000
    FORMERR = 0x0001
    SERVFAIL = 0x0002
    NXDOMAIN = 0x0003
    NOTIMP = 0x0004
    REFUSED = 0x0005

# Flags
class DnsFlags:
    QR = 0x8000  # Query Response flag
    AA = 0x0400  # Authoritative Answer
    RD = 0x0100  # Recursion Desired
    RA = 0x0080  # Recursion Available
