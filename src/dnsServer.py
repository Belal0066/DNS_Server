#dnsServer.py
import logfromat as prntlog

from rslvrDns import *

import logging
import argparse
import os

import socket
import threading
import atexit
import signal
import sys

SERVER_IP = '127.0.0.66'

parser = argparse.ArgumentParser(description='DNS Server')
parser.add_argument('-n', '--new', action='store_true', help='logs 3la ndhafa')
args = parser.parse_args()

if args.new and os.path.exists('logs.log'):
    open('logs.log', 'w').close()


logging.basicConfig(filename='logs.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

atexit.register(lambda: prntlog.logger.stop())

ascii_t = '''
╔╦╗╦ ╦╔═╗  ╔═╗╔═╗╦═╗╦  ╦╔═╗╦═╗  ╦ ╦╔═╗╔═╗  ╔═╗╔╦╗╔═╗╦═╗╔╦╗╔═╗╔╦╗
 ║ ╠═╣║╣   ╚═╗║╣ ╠╦╝╚╗╔╝║╣ ╠╦╝  ╠═╣╠═╣╚═╗  ╚═╗ ║ ╠═╣╠╦╝ ║ ║╣  ║║
 ╩ ╩ ╩╚═╝  ╚═╝╚═╝╩╚═ ╚╝ ╚═╝╩╚═  ╩ ╩╩ ╩╚═╝  ╚═╝ ╩ ╩ ╩╩╚═ ╩ ╚═╝═╩╝
'''

def signal_handler(sig, frame):
    prntlog.debug_message("\n\n....shutting down the server....slam :)")
    logging.debug("Shutting down the server")
    sock.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind((SERVER_IP, SERVER_PORT))
    prntlog.success_message(f"\n{ascii_t}ip: {SERVER_IP}, port {SERVER_PORT}\n")
    logging.info(f"Server started at ip: {SERVER_IP}, port {SERVER_PORT}")
except Exception as e:
    prntlog.error_message(f"ERROR BINDING TO {SERVER_IP}:{SERVER_PORT}: {e}\n")
    logging.error(f"Error binding to {SERVER_IP}:{SERVER_PORT}: {e}")
    exit(1)

while True:
    prntlog.debug_message("....the server is listening....")
    logging.debug("Server is listening")

    data, addr = sock.recvfrom(512)
    prntlog.info_message_timed(f" <-- Received data")
    logging.info(f"Received data from {addr}")
    client_thread = threading.Thread(target=handle_client, args=(data, addr, sock))
    client_thread.start()





