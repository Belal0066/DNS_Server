#dnsServer.py

import socket
import threading
import atexit

import argparse
import signal
import os
import sys
import logging

import logfromat as prntlog
from rslvrDns import *
from config import *

SERVER_IP_TCP = '127.0.0.66'

ascii_t = '''
╔╦╗╦ ╦╔═╗  ╔═╗╔═╗╦═╗╦  ╦╔═╗╦═╗  ╦ ╦╔═╗╔═╗  ╔═╗╔╦╗╔═╗╦═╗╔╦╗╔═╗╔╦╗
 ║ ╠═╣║╣   ╚═╗║╣ ╠╦╝╚╗╔╝║╣ ╠╦╝  ╠═╣╠═╣╚═╗  ╚═╗ ║ ╠═╣╠╦╝ ║ ║╣  ║║
 ╩ ╩ ╩╚═╝  ╚═╝╚═╝╩╚═ ╚╝ ╚═╝╩╚═  ╩ ╩╩ ╩╚═╝  ╚═╝ ╩ ╩ ╩╩╚═ ╩ ╚═╝═╩╝
'''

def setup_server():
    parser = argparse.ArgumentParser(description='DNS Server')
    parser.add_argument('-n', '--new', action='store_true', help='logs 3la ndhafa')
    args = parser.parse_args()

    if args.new and os.path.exists('logs.log'):
        open('logs.log', 'w').close()

    logging.basicConfig(filename='logs.log', level=logging.DEBUG, 
                        format='%(asctime)s - %(levelname)s - %(message)s')

    atexit.register(lambda: prntlog.logger.stop())

    def signal_handler(sig, frame):
        prntlog.debug_message("\n\n....shutting down the server....slam :)")
        logging.debug("Shutting down the server")
        udp_sock.close()
        tcp_sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Set up UDP server
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_sock.bind((SERVER_IP, SERVER_PORT))
        prntlog.success_message(f"\n{ascii_t}UDP DNS Server running on {SERVER_IP}:{SERVER_PORT}\n")
        logging.info(f"UDP DNS Server started at {SERVER_IP}:{SERVER_PORT}")
    except Exception as e:
        prntlog.error_message(f"ERROR BINDING UDP TO {SERVER_IP}:{SERVER_PORT}: {e}\n")
        logging.error(f"Error binding UDP to {SERVER_IP}:{SERVER_PORT}: {e}")
        exit(1)

    # Set up TCP server
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        tcp_sock.bind((SERVER_IP_TCP, SERVER_PORT))
        tcp_sock.listen(5)
        prntlog.success_message(f"TCP DNS Server running on {SERVER_IP_TCP}:{SERVER_PORT}\n")
        logging.info(f"TCP DNS Server started at {SERVER_IP_TCP}:{SERVER_PORT}")
    except Exception as e:
        prntlog.error_message(f"ERROR BINDING TCP TO {SERVER_IP_TCP}:{SERVER_PORT}: {e}\n")
        logging.error(f"Error binding TCP to {SERVER_IP_TCP}:{SERVER_PORT}: {e}")
        udp_sock.close()
        exit(1)

    # Start TCP listener thread
    tcp_thread = threading.Thread(target=handle_tcp_connections, args=(tcp_sock,))
    tcp_thread.daemon = True
    tcp_thread.start()

    # UDP server loop
    while True:
        try:
            prntlog.debug_message("....the server is listening....")
            logging.debug("Server is listening")

            data, addr = udp_sock.recvfrom(DnsMessage.MAX_UDP_SIZE)
            prntlog.info_message_timed(f" <-- Received UDP data from {addr}")
            logging.info(f"Received UDP data from {addr}")
            
            client_thread = threading.Thread(target=handle_client, args=(data, addr, udp_sock))
            client_thread.start()
        except Exception as e:
            prntlog.error_message(f"Error in UDP server loop: {e}")
            logging.error(f"Error in UDP server loop: {e}")

def handle_tcp_connections(tcp_sock):
    """Handle incoming TCP connections"""
    while True:
        try:
            client_sock, client_addr = tcp_sock.accept()
            prntlog.info_message_timed(f" <-- Accepted TCP connection from {client_addr}")
            logging.info(f"Accepted TCP connection from {client_addr}")
            
            client_thread = threading.Thread(target=handle_tcp_client, args=(client_sock, client_addr))
            client_thread.daemon = True
            client_thread.start()
        except Exception as e:
            prntlog.error_message(f"Error accepting TCP connection: {e}")
            logging.error(f"Error accepting TCP connection: {e}")

if __name__ == "__main__":
    setup_server()