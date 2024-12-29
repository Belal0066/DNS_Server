#rslvrDns.py
from utilDns import *
import logfromat as prntlog
from constsDns import DnsType, DnsClass, DnsFlags, DnsRcode, SERVER_PORT, ROOT_SERVERS

import logging
import socket



SERVER_IP = '127.0.0.66'

# auth
dns_records = {
    'hahalol.com.': '222.222.222.222',
    'test123.com.' : '123.123.123.123'
}


def handle_client(data, addr, sock):
    try:
        decoded_data = decode_dns_message(data)
        query_name = decoded_data['query_name']
        query_type = decoded_data['query_type']
        
        # Ensure query_name ends with a dot
        if not query_name.endswith('.'):
            query_name = query_name + '.'
        
        if query_type == 'A':
            server_info = f"Server:\t\t{SERVER_IP}\nAddress:\t{SERVER_IP}"
            prntlog.info_message(server_info)
        
        
        prntlog.dns_query_message(addr, decoded_data['formatted_message'])
        
        if query_name in dns_records:
            
            addresses = {'A': [dns_records[query_name]], 'AAAA': []}
            response = build_dns_response(data, query_name, addresses)
            sock.sendto(response, addr)
            prntlog.success_message(f"✓ Response sent to {addr}\n  for {query_name} (authoritative)")
            logging.info(f"Response sent to {addr} for {query_name} (authoritative)")
        else:
            
            addresses = recursive_dns_lookup(query_name)
            if addresses:
                
                filtered_addresses = {
                    'A': addresses['A'] if query_type == 'A' else [],
                    'AAAA': addresses['AAAA'] if query_type == 'AAAA' else []
                }
                response = build_dns_response(data, query_name, filtered_addresses)
                sock.sendto(response, addr)
                prntlog.success_message(f"✓ Response sent to {addr}\n  for {query_name} (non-authoritative)")
                logging.info(f"Response sent to {addr} for {query_name} (non-authoritative)")
            else:
                response = build_nxdomain_response(data)
                sock.sendto(response, addr)
                prntlog.warning_message(f"✗ hwa qalk fein?\n Domain {query_name} not found\n NXDOMAIN sent to {addr}")
                logging.warning(f"Domain {query_name} not found. NXDOMAIN sent to {addr}")
    except Exception as e:
        prntlog.error_message(f"\n! Error: hwa qalk fein? {addr}: \n {e} \n --------------------------------------------------")
        logging.error(f"Error handling client {addr}: {e}")


 
def decode_dns_message(raw_message):
    dns_message = convertRaw_msg(raw_message)
    query_type = DnsType.to_text(dns_message.question[0]['type'])
    
    decoded_data = {
        'query_name': str(dns_message.question[0]['name']),
        'query_type': query_type
    }
    
    message_parts = []
    
    message_parts.append("\nQuestion Section:")
    for question in dns_message.question:
        message_parts.append(f"  Name: {question['name']}")
        message_parts.append(f"  Type: {DnsType.to_text(question['type'])}")
        message_parts.append(f"  Class: {DnsClass.to_text(question['class'])}")
    
    decoded_data['formatted_message'] = '\n'.join(message_parts)
    return decoded_data

def build_dns_response(query_data, query_name, addresses=None):
    dns_query = convertRaw_q(query_data) #to do
    response = buildResp(dns_query.id) #to do
    response.flags = DnsFlags.QR  
    response.question = dns_query.question

    if addresses:
        
        if addresses.get('A'):
            answer = buildAns(  #to do
                query_name,
                300,  
                DnsClass.IN,
                DnsType.A,
                *addresses['A']
            )
            response.answer.append(answer)

        
        if addresses.get('AAAA'):
            answer = buildAns( #to do
                query_name,
                300,  
                DnsClass.IN,
                DnsType.AAAA,
                *addresses['AAAA']
            )
            response.answer.append(answer)

        
        if query_name in dns_records:
            response.flags |= DnsFlags.AA

    else:
        response.set_rcode(DnsRcode.NXDOMAIN)

    return response.to_wire()

def handle_dns_query(data, addr, sock):
    
    decoded_data = decode_dns_message(data)  
    query_name = decoded_data['query_name']  
    print("\n### End Message\n")

    
    if query_name in dns_records:
        
        response = build_dns_response(data, query_name)
        try:
            sock.sendto(response, addr)
            prntlog.success_message(f"Sent response to {addr}")
            logging.info(f"Sent response to {addr}")
        except Exception as e:
            prntlog.error_message(f"ERROR SENDING TO {addr}: {e}\n\n\n")
            logging.error(f"Error sending to {addr}: {e}")
    else:
        
        response = data[:2]  
        response += b'\x81\x83'  
        response += b'\x00\x01'  
        response += b'\x00\x00'  
        response += b'\x00\x00'  
        response += data[12:]  
        try:
            sock.sendto(response, addr)
            prntlog.success_message(f"{query_name} is not found\n Sent NXDOMAIN response to {addr}")
            logging.info(f"{query_name} not found. Sent NXDOMAIN response to {addr}")
        except Exception as e:
            prntlog.error_message(f"ERROR SENDING TO {addr}: {e}\n\n\n")
            logging.error(f"Error sending to {addr}: {e}")

def build_nxdomain_response(query_data):
    """Build a properly formatted NXDOMAIN response"""
    dns_query = convertRaw_msg(query_data)
    response = DnsMessage()
    
    # Copy the ID from the query
    response.id = dns_query.id
    
    # Set appropriate flags for NXDOMAIN response
    response.flags = DnsFlags.QR | DnsFlags.RA
    response.flags |= DnsRcode.NXDOMAIN
    
    # Copy the question section from the query
    response.question = dns_query.question
    
    return response.to_wire()

def query_nameserver(nameserver, query_name, query_type):
    """
    Send a DNS query to a specific nameserver and return the response
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    
    # Create DNS query message
    query = buildQ(query_name, query_type)
    
    try:
        wire_query = query.to_wire()
        sock.sendto(wire_query, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
        response = convertRaw_msg(data)
        return response
    except Exception as e:
        logging.error(f"Error querying nameserver {nameserver}: {e}")
        return None
    finally:
        sock.close()

def recursive_dns_lookup(query_name):
    """
    Implement recursive DNS resolution starting from root servers
    """
    results = {'A': set(), 'AAAA': set()}
    visited_nameservers = set()
    max_referrals = 10  # Prevent infinite loops
    referral_count = 0
    
    # Start with root servers
    nameservers = ROOT_SERVERS
    
    while nameservers and referral_count < max_referrals:
        referral_count += 1
        
        for nameserver in nameservers:
            if nameserver in visited_nameservers:
                continue
                
            visited_nameservers.add(nameserver)
            response = query_nameserver(nameserver, query_name, 'A')
            
            if not response:
                continue
            
            # Check for answers
            if response.answer:
                for answer in response.answer:
                    if answer['type'] == DnsType.A:
                        results['A'].add(answer['rdata'])
                    elif answer['type'] == DnsType.AAAA:
                        results['AAAA'].add(answer['rdata'])
                
                if results['A'] or results['AAAA']:
                    return {
                        'A': list(results['A']),
                        'AAAA': list(results['AAAA'])
                    }
            
            # If no answer, look for nameserver referrals
            new_nameservers = []
            ns_names = set()
            
            # First, get NS records from authority section
            for auth in response.authority:
                if auth['type'] == DnsType.NS:
                    ns_names.add(auth['rdata'])
            
            # Then, look for their IP addresses in additional section
            for additional in response.additional:
                if additional['type'] == DnsType.A and additional['name'] in ns_names:
                    new_nameservers.append(additional['rdata'])
            
            if new_nameservers:
                nameservers = [ns for ns in new_nameservers if ns not in visited_nameservers]
                if nameservers:
                    break
            else:
                # If we have NS names but no A records, try to resolve them
                for ns_name in ns_names:
                    ns_results = recursive_dns_lookup(ns_name)
                    if ns_results and ns_results.get('A'):
                        new_nameservers.extend(ns_results['A'])
                
                nameservers = [ns for ns in new_nameservers if ns not in visited_nameservers]
                if nameservers:
                    break
        else:
            break
    
    return None if not (results['A'] or results['AAAA']) else {
        'A': list(results['A']),
        'AAAA': list(results['AAAA'])
    }
