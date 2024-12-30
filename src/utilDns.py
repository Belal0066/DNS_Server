from constsDns import *
from config import *
dns_records = LOCAL_RECORDS


class DnsMessage:
    MAX_UDP_SIZE = 512  # Maximum size for UDP messages
    MAX_TCP_SIZE = 65535  # Maximum size for TCP messages (64KB)

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
        self.is_truncated = False

    def set_rcode(self, rcode):
        """Set the response code in the flags field while preserving other flags"""
        self.flags = (self.flags & 0xFFF0) | (rcode & 0x000F)
        
    def set_tc(self, truncated):
        """Set or clear the TC (truncation) flag"""
        if truncated:
            self.flags |= 0x0200  # Set TC bit
            self.is_truncated = True
        else:
            self.flags &= ~0x0200  # Clear TC bit
            self.is_truncated = False

    def is_tc_set(self):
        """Check if the TC (truncation) flag is set"""
        return bool(self.flags & 0x0200)

    def _encode_name(self, name, wire, name_offsets):
        """
        Encode a domain name with compression.
        Returns the current position after encoding.
        """
        if not name:
            wire.append(0)
            return len(wire)

        # Check if we can use compression
        if name in name_offsets:
            # Add compression pointer (2 bytes with first two bits set)
            offset = name_offsets[name]
            pointer = 0xC000 | offset  # 0xC000 = 11000000 00000000
            wire.extend(pointer.to_bytes(2, 'big'))
            return len(wire)

        # Store the start position of this name
        start_pos = len(wire)
        name_offsets[name] = start_pos

        # Split into labels
        labels = name.split('.')
        
        # Encode each label
        for label in labels:
            if label:  # Skip empty labels
                # Store each part of the name for future compression
                if len(name_offsets) < 255:  # Limit number of stored offsets
                    name_offsets[name] = start_pos
                
                # Encode the label
                length = len(label)
                if length > 63:
                    raise ValueError(f"Label too long: {label}")
                wire.append(length)
                wire.extend(label.encode())
            
            # Move to the next label
            dot_pos = name.find('.', len(label) + 1)
            if dot_pos != -1:
                name = name[dot_pos + 1:]

        # Add terminating zero
        wire.append(0)
        return len(wire)
        
    def to_wire(self, max_size=None):
        """
        Convert message to wire format (bytes) with compression and truncation if needed.
        Args:
            max_size: Maximum size of the message. If None, uses MAX_UDP_SIZE for UDP messages.
        """
        if max_size is None:
            max_size = self.MAX_UDP_SIZE

        # First attempt: try to build the complete message
        wire = bytearray()
        name_offsets = {}

        # Header (12 bytes)
        wire.extend(self.id.to_bytes(2, 'big'))
        wire.extend(self.flags.to_bytes(2, 'big'))
        wire.extend(len(self.question).to_bytes(2, 'big'))
        wire.extend(len(self.answer).to_bytes(2, 'big'))
        wire.extend(len(self.authority).to_bytes(2, 'big'))
        wire.extend(len(self.additional).to_bytes(2, 'big'))

        # Add question section (always include complete question section)
        for q in self.question:
            name = q['name']
            if not name.endswith('.'):
                name += '.'
            self._encode_name(name, wire, name_offsets)
            wire.extend(q['type'].to_bytes(2, 'big'))
            wire.extend(q['class'].to_bytes(2, 'big'))

        # If we've already exceeded max_size, truncate and set TC flag
        if len(wire) > max_size:
            self.set_tc(True)
            return bytes(wire[:max_size])

        # Try to add answer sections
        answer_wire = bytearray()
        for ans in self.answer:
            section_start = len(answer_wire)
            
            if isinstance(ans, bytes):
                answer_wire.extend(ans)
            else:
                name = ans['name']
                if not name.endswith('.'):
                    name += '.'
                self._encode_name(name, answer_wire, name_offsets)
                answer_wire.extend(ans['type'].to_bytes(2, 'big'))
                answer_wire.extend(ans['class'].to_bytes(2, 'big'))
                answer_wire.extend(ans['ttl'].to_bytes(4, 'big'))
                
                rdata = ans['rdata']
                if isinstance(rdata, str) and ans['type'] == DnsType.A:
                    rdata = bytes(map(int, rdata.split('.')))
                elif ans['type'] == DnsType.NS:
                    rdata_wire = bytearray()
                    self._encode_name(rdata, rdata_wire, name_offsets)
                    rdata = bytes(rdata_wire)
                
                answer_wire.extend(len(rdata).to_bytes(2, 'big'))
                answer_wire.extend(rdata)

            # Check if adding this answer would exceed max_size
            if len(wire) + len(answer_wire) > max_size:
                # Truncate at the last complete answer
                answer_wire = answer_wire[:section_start]
                self.set_tc(True)
                break

        wire.extend(answer_wire)
        return bytes(wire)

    def to_tcp_wire(self):
        """
        Convert message to TCP wire format (with 2-byte length prefix)
        """
        # Get the message in wire format without size limit
        message_wire = self.to_wire(max_size=self.MAX_TCP_SIZE)
        
        # Add 2-byte length prefix
        length = len(message_wire)
        if length > self.MAX_TCP_SIZE:
            raise ValueError(f"Message too large for TCP: {length} bytes")
        
        return length.to_bytes(2, 'big') + message_wire

    @classmethod
    def from_tcp_wire(cls, data):
        """
        Parse a TCP format DNS message (with 2-byte length prefix)
        """
        if len(data) < 2:
            raise ValueError("TCP DNS message too short")
        
        # Extract message length
        length = int.from_bytes(data[0:2], 'big')
        
        # Verify length
        if length > cls.MAX_TCP_SIZE:
            raise ValueError(f"TCP message length too large: {length}")
        if len(data) < length + 2:
            raise ValueError("Incomplete TCP message")
        
        # Parse the actual message
        return convertRaw_msg(data[2:2+length])

def parse_name(data, offset):
    """Parse a domain name from DNS wire format with compression support"""
    labels = []
    max_jumps = 10  # Prevent infinite loops
    jumps = 0
    
    while True:
        if jumps >= max_jumps:
            raise ValueError("Too many compression pointers")
        
        # Get the length byte
        length = data[offset]
        
        # Check if it's a pointer
        if (length & 0xC0) == 0xC0:
            if jumps == 0:
                # Save the location after the first pointer for the return value
                pointer_offset = offset + 2
            
            # Extract pointer value (lower 14 bits)
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            jumps += 1
            continue
        
        # Regular label
        if length == 0:
            break
        
        # Extract the label
        offset += 1
        label = data[offset:offset + length].decode('ascii')
        labels.append(label)
        offset += length
    
    # Return the name and the offset after the name
    return '.'.join(labels) + '.', pointer_offset if jumps > 0 else offset + 1

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
    """Build a DNS answer section with support for all record types"""
    answer = bytearray()
    
    # Add name using compression pointer to question name
    answer.extend(b'\xc0\x0c')  # Pointer to name in question section
    
    # Add type, class, TTL
    answer.extend(rdtype.to_bytes(2, 'big'))
    answer.extend(rdclass.to_bytes(2, 'big'))
    answer.extend(ttl.to_bytes(4, 'big'))
    
    # Add RDATA based on record type
    if rdtype == DnsType.A:
        for addr in addresses:
            rdata = bytes(map(int, addr.split('.')))
            answer.extend(len(rdata).to_bytes(2, 'big'))
            answer.extend(rdata)
    elif rdtype == DnsType.NS:
        for ns in addresses:
            rdata = encode_name(ns)
            answer.extend(len(rdata).to_bytes(2, 'big'))
            answer.extend(rdata)
    elif rdtype == DnsType.CNAME:
        for cname in addresses:
            rdata = encode_name(cname)
            answer.extend(len(rdata).to_bytes(2, 'big'))
            answer.extend(rdata)
    elif rdtype == DnsType.MX:
        for pref, mx in addresses:
            rdata = bytearray()
            rdata.extend(pref.to_bytes(2, 'big'))
            rdata.extend(encode_name(mx))
            answer.extend(len(rdata).to_bytes(2, 'big'))
            answer.extend(rdata)
    elif rdtype == DnsType.PTR:
        for ptr in addresses:
            rdata = encode_name(ptr)
            answer.extend(len(rdata).to_bytes(2, 'big'))
            answer.extend(rdata)
    
    return bytes(answer)

def encode_name(name, name_offsets=None):
    """Encode a domain name with compression"""
    if name_offsets is None:
        name_offsets = {}
    
    if not name:
        return b'\x00'
    
    if not name.endswith('.'):
        name = name + '.'
    
    # Check if we can use compression
    if name in name_offsets:
        pointer = 0xC000 | name_offsets[name]
        return pointer.to_bytes(2, 'big')
    
    result = bytearray()
    start_offset = len(result)
    
    labels = name.split('.')
    for label in labels[:-1]:  # Skip the last empty label
        if not label:
            continue
        
        # Store offset for future compression
        current_name = '.'.join(labels[labels.index(label):])
        if current_name not in name_offsets:
            name_offsets[current_name] = start_offset + len(result)
        
        # Add the label length and label
        result.append(len(label))
        result.extend(label.encode('ascii'))
    
    result.append(0)  # Add the terminating zero length
    return bytes(result)

def buildQ(qname, qtype):
    """Build a DNS query message with support for all record types"""
    msg = DnsMessage()
    
    # Generate random ID
    import random
    msg.id = random.randint(0, 65535)
    
    # Set flags for standard query
    msg.flags = DnsFlags.RD  # Set Recursion Desired
    
    # Add question
    qtype_map = {
        'A': DnsType.A,
        'AAAA': DnsType.AAAA,
        'NS': DnsType.NS,
        'CNAME': DnsType.CNAME,
        'MX': DnsType.MX,
        'PTR': DnsType.PTR
    }
    
    msg.question.append({
        'name': qname if qname.endswith('.') else qname + '.',
        'type': qtype_map.get(qtype, DnsType.A),  # Default to A if type not recognized
        'class': DnsClass.IN
    })
    
    return msg

def build_dns_response(query_data, query_name, records=None):
    """Build a DNS response message with support for all record types"""
    dns_query = convertRaw_q(query_data)
    response = buildResp(dns_query.id)
    response.flags = DnsFlags.QR | DnsFlags.RA  # Set QR and RA flags
    response.question = dns_query.question

    if records:
        # Set NOERROR for successful responses
        response.set_rcode(DnsRcode.NOERROR)
        
        # Add answers for each record type
        for rtype, rdata in records.items():
            if not rdata:
                continue
                
            if rtype == 'A':
                answer = buildAns(query_name, 300, DnsClass.IN, DnsType.A, *rdata)
                response.answer.append(answer)
            elif rtype == 'AAAA':
                answer = buildAns(query_name, 300, DnsClass.IN, DnsType.AAAA, *rdata)
                response.answer.append(answer)
            elif rtype == 'NS':
                answer = buildAns(query_name, 300, DnsClass.IN, DnsType.NS, *rdata)
                response.answer.append(answer)
            elif rtype == 'CNAME':
                answer = buildAns(query_name, 300, DnsClass.IN, DnsType.CNAME, *rdata)
                response.answer.append(answer)
            elif rtype == 'MX':
                answer = buildAns(query_name, 300, DnsClass.IN, DnsType.MX, *rdata)
                response.answer.append(answer)
            elif rtype == 'PTR':
                answer = buildAns(query_name, 300, DnsClass.IN, DnsType.PTR, *rdata)
                response.answer.append(answer)

        if query_name in dns_records:
            response.flags |= DnsFlags.AA  # Set AA flag for authoritative answers

    else:
        response.set_rcode(DnsRcode.NXDOMAIN)

    return response

