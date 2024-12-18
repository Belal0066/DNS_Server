#dnsServer.py
import logfromat as prntlog
from dnsData import *

import socket
import threading
import atexit

atexit.register(lambda: prntlog.logger.stop())

ascii_art = '''
╔╦╗╦ ╦╔═╗  ╔═╗╔═╗╦═╗╦  ╦╔═╗╦═╗  ╦ ╦╔═╗╔═╗  ╔═╗╔╦╗╔═╗╦═╗╔╦╗╔═╗╔╦╗
 ║ ╠═╣║╣   ╚═╗║╣ ╠╦╝╚╗╔╝║╣ ╠╦╝  ╠═╣╠═╣╚═╗  ╚═╗ ║ ╠═╣╠╦╝ ║ ║╣  ║║
 ╩ ╩ ╩╚═╝  ╚═╝╚═╝╩╚═ ╚╝ ╚═╝╩╚═  ╩ ╩╩ ╩╚═╝  ╚═╝ ╩ ╩ ╩╩╚═ ╩ ╚═╝═╩╝
'''

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind((SERVER_IP, SERVER_PORT))
    prntlog.success_message(f"\n{ascii_art}\nip: {SERVER_IP}, port {SERVER_PORT}\n")
except Exception as e:
    prntlog.error_message(f"ERROR BINDING TO {SERVER_PORT}: {e}\n")
    exit(1)

while True:
    prntlog.debug_message("....the server is listening....")

    data, addr = sock.recvfrom(512)
    prntlog.info_message_timed(f" <-- Received data")
    client_thread = threading.Thread(target=handle_client, args=(data, addr, sock))
    client_thread.start()





