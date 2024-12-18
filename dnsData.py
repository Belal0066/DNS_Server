import logfromat as prntlog

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rdata

import socket
import threading



# Define some DNS records for your authoritative domain
dns_records = {
    'elbolbol.com.': '111.111.111.111',  
    'hahalol.com.': '222.222.222.222',
    'test123.com.' : '123.123.123.123'
}


def handle_client(data, addr, sock):
    try:
        decoded_data = decode_dns_message(data)
        query_name = decoded_data['query_name']
        
        # Log the complete DNS message in a structured format
        prntlog.dns_query_message(addr, decoded_data['formatted_message'])
        
        if query_name in dns_records:
            response = build_dns_response(data, query_name)
            sock.sendto(response, addr)
            prntlog.success_message(f"✓ Response sent to {addr} for {query_name}")
        else:
            response = build_nxdomain_response(data)
            sock.sendto(response, addr)
            prntlog.warning_message(f"✗ Domain {query_name} not found - NXDOMAIN sent to {addr}")
    except Exception as e:
        prntlog.error_message(f"! Error handling client {addr}: {e}")


 
def decode_dns_message(raw_message):
    dns_message = dns.message.from_wire(raw_message)
    decoded_data = {'query_name': str(dns_message.question[0].name)}
    
    message_parts = []

    f = 0
    if f:
        message_parts.append(f"Transaction ID: {hex(dns_message.id)}")
        message_parts.append(f"QR: {'Response' if dns_message.flags & 0x8000 else 'Query'}")
        message_parts.append(f"Opcode: {dns_message.opcode()}")
        message_parts.append(f"AA: {'Authoritative Answer' if dns_message.flags & 0x0400 else 'Not Authoritative'}")
        message_parts.append(f"TC: {'Truncated' if dns_message.flags & 0x0200 else 'Not Truncated'}")
        message_parts.append(f"RD: {'Recursion Desired' if dns_message.flags & 0x0100 else 'Recursion Not Desired'}")
        message_parts.append(f"RA: {'Recursion Available' if dns_message.flags & 0x0080 else 'Recursion Not Available'}")
        message_parts.append(f"RCODE: {dns_message.rcode()}")
        
    message_parts.append("\nQuestion Section:")
    for question in dns_message.question:
        message_parts.append(f"  Name: {question.name}")
        message_parts.append(f"  Type: {dns.rdatatype.to_text(question.rdtype)}")
        message_parts.append(f"  Class: {dns.rdataclass.to_text(question.rdclass)}")
    
    decoded_data['formatted_message'] = '\n'.join(message_parts)
    return decoded_data

def build_dns_response(query_data, query_name):
    # Parse the original query data using dnspython
    dns_query = dns.message.from_wire(query_data)
    
    # Create a new response message
    response = dns.message.Message(dns_query.id)
    response.flags = dns.flags.QR | dns.flags.AA  # Response + Authoritative Answer
    response.question = dns_query.question  # Copy the question section
    
    # Check if the queried domain is in the authoritative records
    if query_name in dns_records:
        # Create an RRset for the answer
        answer = dns.rrset.from_text(
            query_name,                # Domain name
            300,                       # TTL (time to live)
            dns.rdataclass.IN,         # Class IN (Internet)
            dns.rdatatype.A,           # Type A (IPv4 address)
            dns_records[query_name]    # IP address
        )
        response.answer.append(answer)
    else:
        # Set NXDOMAIN response code for non-existent domains
        response.set_rcode(dns.rcode.NXDOMAIN)
    
    # Build the response message to send over the wire
    return response.to_wire()

def handle_dns_query(data, addr, sock):
    # Decode DNS message to extract domain name being queried
    decoded_data = decode_dns_message(data)  # This function now prints out the decoded details
    query_name = decoded_data['query_name']  # Extracting the domain name being queried
    print("\n### End Message\n")

    # Check if the query is for a domain we are authoritative for
    if query_name in dns_records:
        # Domain is in our records, build a DNS response with the appropriate record
        response = build_dns_response(data, query_name)
        try:
            sock.sendto(response, addr)
            prntlog.success_message(f"Sent response to {addr}")
        except Exception as e:
            prntlog.error_message(f"ERROR SENDING TO {addr}: {e}\n\n\n")
    else:
        # Domain is not found in our authoritative records, respond with NXDOMAIN
        response = data[:2]  # Copy the transaction ID
        response += b'\x81\x83'  # Flags: standard query response, NXDOMAIN (non-existent domain)
        response += b'\x00\x01'  # 1 question
        response += b'\x00\x00'  # 0 answer (no records)
        response += b'\x00\x00'  # No authority or additional records
        response += data[12:]  # Copy the question section from the original query
        try:
            sock.sendto(response, addr)
            prntlog.success_message(f"{query_name} is not found\nSent NXDOMAIN response to {addr}")
        except Exception as e:
            prntlog.error_message(f"ERROR SENDING TO {addr}: {e}\n\n\n")

def build_nxdomain_response(query_data):
    response = query_data[:2]  # Copy the transaction ID
    response += b'\x81\x83'    # Flags: standard query response, NXDOMAIN
    response += b'\x00\x01'    # 1 question
    response += b'\x00\x00'    # 0 answer
    response += b'\x00\x00'    # No authority or additional records
    response += query_data[12:]  # Copy the question section
    return response
