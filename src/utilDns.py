from constsDns import DnsType, DnsClass, DnsFlags, DnsRcode, SERVER_PORT, ROOT_SERVERS


class DnsMessage:
    def __init__(self):
        self.id = 0
        self.flags = 0
        self.question = []
        self.answer = []
        self.authority = []
        self.additional = []
        self.rdtype = None
        self.rdclass = None
        self.name = None

    def to_wire(self):
        """Convert message to wire format (bytes)"""
        wire = bytearray()
        
        # Header (12 bytes)
        wire.extend(self.id.to_bytes(2, 'big'))
        wire.extend(self.flags.to_bytes(2, 'big'))
        wire.extend(len(self.question).to_bytes(2, 'big'))
        wire.extend(len(self.answer).to_bytes(2, 'big'))
        wire.extend(len(self.authority).to_bytes(2, 'big'))
        wire.extend(len(self.additional).to_bytes(2, 'big'))
        
        # Add question section
        for q in self.question:
            # Add name
            name = q['name']
            if not name.endswith('.'):
                name += '.'
            for part in name.split('.'):
                if part:
                    wire.append(len(part))
                    wire.extend(part.encode())
            wire.append(0)  # Root label
            
            # Add type and class
            wire.extend(q['type'].to_bytes(2, 'big'))
            wire.extend(q['class'].to_bytes(2, 'big'))
        
        # Add answer sections
        for ans in self.answer:
            if isinstance(ans, bytes):
                wire.extend(ans)
            else:
                # Handle structured answer data
                wire.extend(b'\xc0\x0c')  # Compression pointer to question name
                wire.extend(ans['type'].to_bytes(2, 'big'))
                wire.extend(ans['class'].to_bytes(2, 'big'))
                wire.extend(ans['ttl'].to_bytes(4, 'big'))
                rdata = ans['rdata']
                if isinstance(rdata, str) and ans['type'] == DnsType.A:
                    # Convert IP address string to bytes
                    rdata = bytes(map(int, rdata.split('.')))
                wire.extend(len(rdata).to_bytes(2, 'big'))
                wire.extend(rdata)
        
        return bytes(wire)

def parse_name(raw_data, offset):
    """Parse a DNS name starting at the given offset in raw_data"""
    parts = []
    original_offset = offset
    try:
        while True:
            length = raw_data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0 == 0xC0:  # Compression pointer
                pointer = int.from_bytes(raw_data[offset:offset+2], 'big') & 0x3FFF
                if pointer >= original_offset:  # Prevent forward references
                    raise ValueError("Invalid compression pointer")
                name, _ = parse_name(raw_data, pointer)
                return name, offset + 2
            offset += 1
            if offset + length > len(raw_data):
                raise ValueError("Name extends beyond message")
            parts.append(raw_data[offset:offset+length].decode())
            offset += length
    except (IndexError, UnicodeDecodeError) as e:
        raise ValueError(f"Error parsing name: {e}")
    return '.'.join(parts), offset

def convertRaw_msg(raw_data):
    """Convert raw DNS message bytes into a DnsMessage object"""
    msg = DnsMessage()
    
    # Parse header (first 12 bytes)
    msg.id = int.from_bytes(raw_data[0:2], 'big')
    msg.flags = int.from_bytes(raw_data[2:4], 'big')
    qdcount = int.from_bytes(raw_data[4:6], 'big')
    ancount = int.from_bytes(raw_data[6:8], 'big')
    nscount = int.from_bytes(raw_data[8:10], 'big')
    arcount = int.from_bytes(raw_data[10:12], 'big')
    
    # Parse question section (starts at byte 12)
    offset = 12
    for _ in range(qdcount):
        qname, offset = parse_name(raw_data, offset)
        qtype = int.from_bytes(raw_data[offset:offset+2], 'big')
        qclass = int.from_bytes(raw_data[offset+2:offset+4], 'big')
        offset += 4
        
        question = {
            'name': qname,
            'type': qtype,
            'class': qclass
        }
        msg.question.append(question)
        
        # Store these for easier access
        msg.name = qname
        msg.rdtype = qtype
        msg.rdclass = qclass
    
    # Parse answer section
    for _ in range(ancount):
        name, offset = parse_name(raw_data, offset)
        rtype = int.from_bytes(raw_data[offset:offset+2], 'big')
        rclass = int.from_bytes(raw_data[offset+2:offset+4], 'big')
        ttl = int.from_bytes(raw_data[offset+4:offset+8], 'big')
        rdlength = int.from_bytes(raw_data[offset+8:offset+10], 'big')
        offset += 10
        
        if rtype == DnsType.A:
            rdata = '.'.join(str(b) for b in raw_data[offset:offset+rdlength])
        elif rtype == DnsType.NS:
            rdata, _ = parse_name(raw_data, offset)
        else:
            rdata = raw_data[offset:offset+rdlength]
            
        answer = {
            'name': name,
            'type': rtype,
            'class': rclass,
            'ttl': ttl,
            'rdata': rdata
        }
        msg.answer.append(answer)
        offset += rdlength
    
    # Parse authority section
    for _ in range(nscount):
        name, offset = parse_name(raw_data, offset)
        rtype = int.from_bytes(raw_data[offset:offset+2], 'big')
        rclass = int.from_bytes(raw_data[offset+2:offset+4], 'big')
        ttl = int.from_bytes(raw_data[offset+4:offset+8], 'big')
        rdlength = int.from_bytes(raw_data[offset+8:offset+10], 'big')
        offset += 10
        
        if rtype == DnsType.NS:
            rdata, _ = parse_name(raw_data, offset)
        else:
            rdata = raw_data[offset:offset+rdlength]
            
        authority = {
            'name': name,
            'type': rtype,
            'class': rclass,
            'ttl': ttl,
            'rdata': rdata
        }
        msg.authority.append(authority)
        offset += rdlength
    
    # Parse additional section
    for _ in range(arcount):
        name, offset = parse_name(raw_data, offset)
        rtype = int.from_bytes(raw_data[offset:offset+2], 'big')
        rclass = int.from_bytes(raw_data[offset+2:offset+4], 'big')
        ttl = int.from_bytes(raw_data[offset+4:offset+8], 'big')
        rdlength = int.from_bytes(raw_data[offset+8:offset+10], 'big')
        offset += 10
        
        if rtype == DnsType.A:
            rdata = '.'.join(str(b) for b in raw_data[offset:offset+rdlength])
        else:
            rdata = raw_data[offset:offset+rdlength]
            
        additional = {
            'name': name,
            'type': rtype,
            'class': rclass,
            'ttl': ttl,
            'rdata': rdata
        }
        msg.additional.append(additional)
        offset += rdlength
    
    return msg

def convertRaw_q(raw_data):
    """Alias for convertRaw_msg for clarity when handling queries"""
    return convertRaw_msg(raw_data)

def buildResp(id_or_msg):
    """Build a DNS response message"""
    msg = DnsMessage()
    
    if isinstance(id_or_msg, bytes):
        query_msg = convertRaw_msg(id_or_msg)
        msg.id = query_msg.id
        msg.question = query_msg.question
    else:
        msg.id = id_or_msg
    
    msg.flags = DnsFlags.QR | DnsFlags.AA | DnsFlags.RA
    return msg

def buildAns(name, ttl, rdclass, rdtype, *addresses):
    """Build a DNS answer section"""
    answer = bytearray()
    
    # Add name using compression pointer to question name
    answer.extend(b'\xc0\x0c')  # Pointer to name in question section
    
    # Add type, class, TTL
    answer.extend(rdtype.to_bytes(2, 'big'))
    answer.extend(rdclass.to_bytes(2, 'big'))
    answer.extend(ttl.to_bytes(4, 'big'))
    
    # Add RDATA
    if rdtype == DnsType.A:
        for addr in addresses:
            rdata = bytes(map(int, addr.split('.')))
            answer.extend(len(rdata).to_bytes(2, 'big'))
            answer.extend(rdata)
    
    return bytes(answer)

def buildQ(qname, qtype):
    """Build a DNS query message"""
    msg = DnsMessage()
    
    # Generate random ID
    import random
    msg.id = random.randint(0, 65535)
    
    # Set flags for standard query
    msg.flags = DnsFlags.RD  # Set Recursion Desired
    
    # Add question
    msg.question.append({
        'name': qname if qname.endswith('.') else qname + '.',
        'type': DnsType.A if qtype == 'A' else DnsType.AAAA,
        'class': DnsClass.IN
    })
    
    return msg