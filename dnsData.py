#dndData.py

import logfromat as prntlog
import logging
import socket

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rdata
import dns.resolver



SERVER_IP = '127.0.0.66'
# SERVER_IP = '192.168.1.6'
SERVER_PORT = 53

ROOT_SERVERS = [
    '198.41.0.4',    # a.root-servers.net
    '199.9.14.201',  # b.root-servers.net
    '192.33.4.12',   # c.root-servers.net
    '199.7.91.13',   # d.root-servers.net
    '192.203.230.10' # e.root-servers.net
]




dns_records = {
    'elbolbol.com.': '111.111.111.111',  
    'hahalol.com.': '222.222.222.222',
    'test123.com.' : '123.123.123.123'
}





def handle_client(data, addr, sock):
    try:
        decoded_data = decode_dns_message(data)
        query_name = decoded_data['query_name']
        query_type = decoded_data['query_type']
        
        
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
    dns_message = dns.message.from_wire(raw_message)
    query_type = dns.rdatatype.to_text(dns_message.question[0].rdtype)
    
    decoded_data = {
        'query_name': str(dns_message.question[0].name),
        'query_type': query_type
    }
    
    message_parts = []
    
    message_parts.append("\nQuestion Section:")
    for question in dns_message.question:
        message_parts.append(f"  Name: {question.name}")
        message_parts.append(f"  Type: {dns.rdatatype.to_text(question.rdtype)}")
        message_parts.append(f"  Class: {dns.rdataclass.to_text(question.rdclass)}")
    
    decoded_data['formatted_message'] = '\n'.join(message_parts)
    return decoded_data

def build_dns_response(query_data, query_name, addresses=None):
    dns_query = dns.message.from_wire(query_data)
    response = dns.message.Message(dns_query.id)
    response.flags = dns.flags.QR  
    response.question = dns_query.question

    if addresses:
        
        if addresses.get('A'):
            answer = dns.rrset.from_text(
                query_name,
                300,  
                dns.rdataclass.IN,
                dns.rdatatype.A,
                *addresses['A']
            )
            response.answer.append(answer)

        
        if addresses.get('AAAA'):
            answer = dns.rrset.from_text(
                query_name,
                300,  
                dns.rdataclass.IN,
                dns.rdatatype.AAAA,
                *addresses['AAAA']
            )
            response.answer.append(answer)

        
        if query_name in dns_records:
            response.flags |= dns.flags.AA

    else:
        response.set_rcode(dns.rcode.NXDOMAIN)

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
    response = query_data[:2]  
    response += b'\x81\x83'    
    response += b'\x00\x01'    
    response += b'\x00\x00'    
    response += b'\x00\x00'    
    response += query_data[12:]  
    return response

def query_nameserver(nameserver, query_name, query_type):
    """
    Send a DNS query to a specific nameserver and return the response
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    
    # Create DNS query message
    query = dns.message.make_query(query_name, query_type)
    
    try:
        sock.sendto(query.to_wire(), (nameserver, 53))
        data, _ = sock.recvfrom(4096)
        response = dns.message.from_wire(data)
        return response
    except Exception as e:
        return None
    finally:
        sock.close()

def recursive_dns_lookup(query_name):
    """
    Implement recursive DNS resolution starting from root servers
    """
    results = {'A': set(), 'AAAA': set()}
    
    # Start with root servers
    nameservers = ROOT_SERVERS
    
    while nameservers:
        for nameserver in nameservers:
            response = query_nameserver(nameserver, query_name, 'A')
            
            if not response:
                continue
                
            # Check for answers
            if response.answer:
                for rrset in response.answer:
                    for rdata in rrset:
                        if rdata.rdtype == dns.rdatatype.A:
                            results['A'].add(str(rdata))
                        elif rdata.rdtype == dns.rdatatype.AAAA:
                            results['AAAA'].add(str(rdata))
                return {
                    'A': list(results['A']),
                    'AAAA': list(results['AAAA'])
                }
            
            # If no answer, look for nameserver referrals
            new_nameservers = []
            
            # Check additional section for nameserver IPs
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    for rdata in rrset:
                        new_nameservers.append(str(rdata))
            
            # If we found new nameservers, use them for next iteration
            if new_nameservers:
                nameservers = new_nameservers
                break
        else:
            # If we didn't find any new nameservers, stop
            break
    
    return None if not (results['A'] or results['AAAA']) else {
        'A': list(results['A']),
        'AAAA': list(results['AAAA'])
    }
