# dndData.py

import logfromat as prntlog

import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.rdata
import dns.resolver



SERVER_IP = '127.0.0.66'
SERVER_PORT = 53




dns_records = {
    'elbolbol.com.': '111.111.111.111',  
    'hahalol.com.': '222.222.222.222',
    'test123.com.' : '123.123.123.123'
}


SERVER_IP = '127.0.0.66'
SERVER_PORT = 53


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
            else:
                response = build_nxdomain_response(data)
                sock.sendto(response, addr)
                prntlog.warning_message(f"✗ hwa qalk fein?\n Domain {query_name} not found\n NXDOMAIN sent to {addr}")
    except Exception as e:
        prntlog.error_message(f"\n! Error: hwa qalk fein? {addr}: \n {e} \n --------------------------------------------------")


 
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
        except Exception as e:
            prntlog.error_message(f"ERROR SENDING TO {addr}: {e}\n\n\n")
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
        except Exception as e:
            prntlog.error_message(f"ERROR SENDING TO {addr}: {e}\n\n\n")

def build_nxdomain_response(query_data):
    response = query_data[:2]  
    response += b'\x81\x83'    
    response += b'\x00\x01'    
    response += b'\x00\x00'    
    response += b'\x00\x00'    
    response += query_data[12:]  
    return response

def recursive_dns_lookup(query_name):
    resolver = dns.resolver.Resolver()
    
    results = {'A': set(), 'AAAA': set()}
    
    try:
        
        answers = resolver.resolve(query_name, 'A')
        for rdata in answers:
            results['A'].add(str(rdata))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass

    try:
        
        answers = resolver.resolve(query_name, 'AAAA')
        for rdata in answers:
            results['AAAA'].add(str(rdata))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass

    
    return {
        'A': list(results['A']),
        'AAAA': list(results['AAAA'])
    } if (results['A'] or results['AAAA']) else None
