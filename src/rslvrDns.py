#rslvrDns.py
from utilDns import *
import logfromat as prntlog
from constsDns import DnsType, DnsClass, DnsFlags, DnsRcode, SERVER_PORT, ROOT_SERVERS

import logging
import socket
import threading

from config import *


# auth
dns_records = LOCAL_RECORDS


def handle_client(data, addr, sock):
    try:
        # Try to decode the DNS message
        try:
            decoded_data = decode_dns_message(data)
            query_name = decoded_data['query_name']
            query_type = decoded_data['query_type']
        except ValueError as e:
            # Format error - invalid query
            response = buildResp(int.from_bytes(data[0:2], 'big'))  # Get ID from raw data
            response.set_rcode(DnsRcode.FORMERR)
            sock.sendto(response.to_wire(), addr)
            prntlog.error_message(f"Format error handling query from {addr}: {e}")
            logging.error(f"Format error handling query from {addr}: {e}")
            return
        
        # Ensure query_name ends with a dot
        if not query_name.endswith('.'):
            query_name = query_name + '.'
        
        if query_type == 'A':
            server_info = f"Server:\t\t{SERVER_IP}\nAddress:\t{SERVER_IP}"
            prntlog.info_message(server_info)
        
        prntlog.dns_query_message(addr, decoded_data['formatted_message'])
        
        # Check if query type is supported
        if query_type not in ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR']:
            response = buildResp(data)
            response.question = decoded_data['question']
            response.set_rcode(DnsRcode.NOTIMP)
            sock.sendto(response.to_wire(), addr)
            prntlog.warning_message(f"Unsupported query type {query_type} from {addr}")
            logging.warning(f"Unsupported query type {query_type} from {addr}")
            return
        
        if query_name in dns_records:
            record = dns_records[query_name]
            # Handle CNAME records first
            if query_type != 'CNAME' and record['CNAME']:
                # If the record has a CNAME and we're not explicitly looking for the CNAME,
                # we should return both the CNAME and the target's records
                cname_target = record['CNAME'][0]
                response = build_dns_response(data, query_name, {'CNAME': record['CNAME']})
                
                if cname_target in dns_records:
                    target_record = dns_records[cname_target]
                    if target_record[query_type]:
                        # Add the target's records of the requested type
                        response.answer.extend(build_dns_response(data, cname_target, 
                            {query_type: target_record[query_type]}).answer)
                
                sock.sendto(response.to_wire(), addr)
                prntlog.success_message(f"✓ Response sent to {addr}\n  for {query_name} (authoritative)")
                logging.info(f"Response sent to {addr} for {query_name} (authoritative)")
                return
            
            # Handle direct record matches
            if record[query_type]:
                response = build_dns_response(data, query_name, {query_type: record[query_type]})
                sock.sendto(response.to_wire(), addr)
                prntlog.success_message(f"✓ Response sent to {addr}\n  for {query_name} (authoritative)")
                logging.info(f"Response sent to {addr} for {query_name} (authoritative)")
                return
            else:
                # No record of requested type exists
                response = buildResp(data)
                response.question = decoded_data['question']
                response.set_rcode(DnsRcode.NOERROR)  # Domain exists but no record of this type
                sock.sendto(response.to_wire(), addr)
                prntlog.warning_message(f"No {query_type} record for {query_name}")
                logging.warning(f"No {query_type} record for {query_name}")
                return
        else:
            try:
                # For PTR queries, we need to handle them differently
                if query_type == 'PTR':
                    # Check if it's a reverse lookup query
                    if query_name.endswith('.in-addr.arpa.'):
                        # Extract the IP address from the query name
                        ip_parts = query_name.replace('.in-addr.arpa.', '').split('.')
                        ip_parts.reverse()
                        ip = '.'.join(ip_parts)
                        
                        # Look for a matching PTR record
                        for domain, records in dns_records.items():
                            if records['A'] and ip in records['A']:
                                response = build_dns_response(data, query_name, {'PTR': [domain]})
                                sock.sendto(response.to_wire(), addr)
                                prntlog.success_message(f"✓ PTR Response sent to {addr}\n  for {query_name}")
                                return
                
                # For other query types, try recursive lookup
                addresses = recursive_dns_lookup(query_name)
                if addresses:
                    filtered_addresses = {
                        'A': addresses['A'] if query_type == 'A' else [],
                        'AAAA': addresses['AAAA'] if query_type == 'AAAA' else [],
                        'NS': addresses['NS'] if query_type == 'NS' else [],
                        'CNAME': addresses['CNAME'] if query_type == 'CNAME' else [],
                        'MX': addresses['MX'] if query_type == 'MX' else [],
                        'PTR': addresses['PTR'] if query_type == 'PTR' else []
                    }
                    response = build_dns_response(data, query_name, filtered_addresses)
                    sock.sendto(response.to_wire(), addr)
                    prntlog.success_message(f"✓ Response sent to {addr}\n  for {query_name} (non-authoritative)")
                    logging.info(f"Response sent to {addr} for {query_name} (non-authoritative)")
                else:
                    response = buildResp(data)
                    response.question = decoded_data['question']
                    response.set_rcode(DnsRcode.NXDOMAIN)
                    sock.sendto(response.to_wire(), addr)
                    prntlog.warning_message(f"✗ Domain {query_name} not found\n NXDOMAIN sent to {addr}")
                    logging.warning(f"Domain {query_name} not found. NXDOMAIN sent to {addr}")
            except Exception as e:
                response = buildResp(data)
                response.question = decoded_data['question']
                response.set_rcode(DnsRcode.SERVFAIL)
                sock.sendto(response.to_wire(), addr)
                prntlog.error_message(f"Server failure during recursive lookup for {query_name}: {e}")
                logging.error(f"Server failure during recursive lookup for {query_name}: {e}")
                
    except Exception as e:
        # General server failure
        try:
            response = buildResp(int.from_bytes(data[0:2], 'big'))
            response.set_rcode(DnsRcode.SERVFAIL)
            sock.sendto(response.to_wire(), addr)
        except:
            pass  # If we can't even send an error response, just log it
        prntlog.error_message(f"Error handling client {addr}: {e}")
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
    dns_query = convertRaw_q(query_data)
    response = buildResp(dns_query.id)
    response.flags = DnsFlags.QR | DnsFlags.RA  # Set QR and RA flags
    response.question = dns_query.question

    if addresses:
        # Set NOERROR for successful responses
        response.set_rcode(DnsRcode.NOERROR)
        
        if addresses.get('A'):
            answer = buildAns(
                query_name,
                300,  # TTL
                DnsClass.IN,
                DnsType.A,
                *addresses['A']
            )
            response.answer.append(answer)

        if addresses.get('AAAA'):
            answer = buildAns(
                query_name,
                300,  # TTL
                DnsClass.IN,
                DnsType.AAAA,
                *addresses['AAAA']
            )
            response.answer.append(answer)

        if query_name in dns_records:
            response.flags |= DnsFlags.AA  # Set AA flag for authoritative answers

    else:
        response.set_rcode(DnsRcode.NXDOMAIN)

    return response

def handle_dns_query(data, addr, sock):
    """Legacy handler for backward compatibility"""
    try:
        decoded_data = decode_dns_message(data)  
        query_name = decoded_data['query_name']  
        
        if query_name in dns_records:
            response = build_dns_response(data, query_name)
            sock.sendto(response.to_wire(), addr)
            prntlog.success_message(f"Sent response to {addr}")
            logging.info(f"Sent response to {addr}")
        else:
            response = buildResp(data)
            response.question = decoded_data['question']
            response.set_rcode(DnsRcode.NXDOMAIN)
            sock.sendto(response.to_wire(), addr)
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
    results = {
        'A': set(), 
        'AAAA': set(),
        'NS': set(),
        'CNAME': set(),
        'MX': set(),
        'PTR': set()
    }
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
                    elif answer['type'] == DnsType.NS:
                        results['NS'].add(answer['rdata'])
                    elif answer['type'] == DnsType.CNAME:
                        results['CNAME'].add(answer['rdata'])
                    elif answer['type'] == DnsType.MX:
                        results['MX'].add(answer['rdata'])
                    elif answer['type'] == DnsType.PTR:
                        results['PTR'].add(answer['rdata'])
                
                if any(results.values()):
                    return {
                        'A': list(results['A']),
                        'AAAA': list(results['AAAA']),
                        'NS': list(results['NS']),
                        'CNAME': list(results['CNAME']),
                        'MX': list(results['MX']),
                        'PTR': list(results['PTR'])
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
    
    return None if not any(results.values()) else {
        'A': list(results['A']),
        'AAAA': list(results['AAAA']),
        'NS': list(results['NS']),
        'CNAME': list(results['CNAME']),
        'MX': list(results['MX']),
        'PTR': list(results['PTR'])
    }

def handle_tcp_client(sock, addr):
    """Handle a TCP client connection"""
    try:
        # First read the 2-byte length field
        length_data = sock.recv(2)
        if not length_data or len(length_data) != 2:
            logging.error(f"Failed to read TCP message length from {addr}")
            return
        
        length = int.from_bytes(length_data, 'big')
        if length > DnsMessage.MAX_TCP_SIZE:
            logging.error(f"TCP message too large from {addr}: {length}")
            return
        
        # Read the complete message
        data = bytearray()
        remaining = length
        while remaining > 0:
            chunk = sock.recv(min(remaining, 4096))
            if not chunk:
                logging.error(f"Connection closed by {addr} while reading message")
                return
            data.extend(chunk)
            remaining -= len(chunk)
        
        # Process the query
        try:
            decoded_data = decode_dns_message(bytes(data))
            query_name = decoded_data['query_name']
            query_type = decoded_data['query_type']
        except ValueError as e:
            # Format error - invalid query
            response = buildResp(int.from_bytes(data[0:2], 'big'))
            response.set_rcode(DnsRcode.FORMERR)
            send_tcp_response(sock, response)
            return
        
        # Rest of query handling similar to UDP but using TCP response
        if not query_name.endswith('.'):
            query_name = query_name + '.'
        
        if query_type == 'A':
            server_info = f"Server:\t\t{SERVER_IP}\nAddress:\t{SERVER_IP}"
            prntlog.info_message(server_info)
        
        prntlog.dns_query_message(addr, decoded_data['formatted_message'])
        
        if query_type not in ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR']:
            response = buildResp(data)
            response.question = decoded_data['question']
            response.set_rcode(DnsRcode.NOTIMP)
            send_tcp_response(sock, response)
            return
        
        if query_name in dns_records:
            record = dns_records[query_name]
            # Handle CNAME records first
            if query_type != 'CNAME' and record['CNAME']:
                # If the record has a CNAME and we're not explicitly looking for the CNAME,
                # we should return both the CNAME and the target's records
                cname_target = record['CNAME'][0]
                response = build_dns_response(data, query_name, {'CNAME': record['CNAME']})
                
                if cname_target in dns_records:
                    target_record = dns_records[cname_target]
                    if target_record[query_type]:
                        # Add the target's records of the requested type
                        response.answer.extend(build_dns_response(data, cname_target, 
                            {query_type: target_record[query_type]}).answer)
                
                send_tcp_response(sock, response)
                prntlog.success_message(f"✓ TCP Response sent to {addr}\n  for {query_name} (authoritative)")
                return
            
            # Handle direct record matches
            if record[query_type]:
                response = build_dns_response(data, query_name, {query_type: record[query_type]})
                send_tcp_response(sock, response)
                prntlog.success_message(f"✓ TCP Response sent to {addr}\n  for {query_name} (authoritative)")
                return
            else:
                # No record of requested type exists
                response = buildResp(data)
                response.question = decoded_data['question']
                response.set_rcode(DnsRcode.NOERROR)  # Domain exists but no record of this type
                send_tcp_response(sock, response)
                prntlog.warning_message(f"No {query_type} record for {query_name}")
                return
        else:
            try:
                # For PTR queries, we need to handle them differently
                if query_type == 'PTR':
                    # Check if it's a reverse lookup query
                    if query_name.endswith('.in-addr.arpa.'):
                        # Extract the IP address from the query name
                        ip_parts = query_name.replace('.in-addr.arpa.', '').split('.')
                        ip_parts.reverse()
                        ip = '.'.join(ip_parts)
                        
                        # Look for a matching PTR record
                        for domain, records in dns_records.items():
                            if records['A'] and ip in records['A']:
                                response = build_dns_response(data, query_name, {'PTR': [domain]})
                                send_tcp_response(sock, response)
                                prntlog.success_message(f"✓ TCP PTR Response sent to {addr}\n  for {query_name}")
                                return
                
                # For other query types, try recursive lookup
                addresses = recursive_dns_lookup(query_name)
                if addresses:
                    filtered_addresses = {
                        'A': addresses['A'] if query_type == 'A' else [],
                        'AAAA': addresses['AAAA'] if query_type == 'AAAA' else [],
                        'NS': addresses['NS'] if query_type == 'NS' else [],
                        'CNAME': addresses['CNAME'] if query_type == 'CNAME' else [],
                        'MX': addresses['MX'] if query_type == 'MX' else [],
                        'PTR': addresses['PTR'] if query_type == 'PTR' else []
                    }
                    response = build_dns_response(data, query_name, filtered_addresses)
                    send_tcp_response(sock, response)
                    prntlog.success_message(f"✓ TCP Response sent to {addr}\n  for {query_name} (non-authoritative)")
                else:
                    response = buildResp(data)
                    response.question = decoded_data['question']
                    response.set_rcode(DnsRcode.NXDOMAIN)
                    send_tcp_response(sock, response)
                    prntlog.warning_message(f"✗ Domain {query_name} not found\n NXDOMAIN sent to {addr}")
            except Exception as e:
                response = buildResp(data)
                response.question = decoded_data['question']
                response.set_rcode(DnsRcode.SERVFAIL)
                send_tcp_response(sock, response)
                prntlog.error_message(f"Server failure during TCP lookup for {query_name}: {e}")
                
    except Exception as e:
        logging.error(f"Error handling TCP client {addr}: {e}")
    finally:
        try:
            # Ensure all data is sent before closing
            sock.flush() if hasattr(sock, 'flush') else None
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except:
            pass

def send_tcp_response(sock, response):
    """Send a DNS response over TCP with proper format"""
    try:
        # Convert response to wire format without TCP length prefix
        message_wire = response.to_wire(max_size=DnsMessage.MAX_TCP_SIZE)
        
        # Add 2-byte length prefix
        length = len(message_wire)
        wire = length.to_bytes(2, 'big') + message_wire
        
        # Send the complete message
        total_sent = 0
        while total_sent < len(wire):
            sent = sock.send(wire[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            total_sent += sent
            
        # Ensure all data is sent before closing
        sock.flush() if hasattr(sock, 'flush') else None
        
    except Exception as e:
        logging.error(f"Error sending TCP response: {e}")
        raise

def query_nameserver_tcp(nameserver, query_name, query_type):
    """Send a DNS query to a specific nameserver using TCP"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)  # Longer timeout for TCP
    
    try:
        # Connect to the nameserver
        sock.connect((nameserver, 53))
        
        # Create and send the query
        query = buildQ(query_name, query_type)
        wire = query.to_tcp_wire()
        
        # Send the complete message
        total_sent = 0
        while total_sent < len(wire):
            sent = sock.send(wire[total_sent:])
            if sent == 0:
                raise RuntimeError("Socket connection broken")
            total_sent += sent
        
        # Read the response length
        length_data = sock.recv(2)
        if not length_data or len(length_data) != 2:
            return None
            
        length = int.from_bytes(length_data, 'big')
        if length > DnsMessage.MAX_TCP_SIZE:
            logging.error(f"TCP response too large from {nameserver}: {length}")
            return None
            
        # Read the complete response
        data = bytearray()
        remaining = length
        while remaining > 0:
            chunk = sock.recv(min(remaining, 4096))
            if not chunk:
                logging.error(f"Connection closed by {nameserver} while reading response")
                return None
            data.extend(chunk)
            remaining -= len(chunk)
            
        return convertRaw_msg(bytes(data))
        
    except Exception as e:
        logging.error(f"Error in TCP query to {nameserver}: {e}")
        return None
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        except:
            pass

def setup_tcp_server(ip, port):
    """Set up TCP DNS server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind((ip, port))
        sock.listen(5)
        logging.info(f"TCP DNS server listening on {ip}:{port}")
        
        while True:
            client_sock, client_addr = sock.accept()
            client_thread = threading.Thread(
                target=handle_tcp_client,
                args=(client_sock, client_addr)
            )
            client_thread.start()
            
    except Exception as e:
        logging.error(f"TCP server error: {e}")
    finally:
        sock.close()
