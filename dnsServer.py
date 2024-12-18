#dnsServer.py
import logfromat as prntlog
from dnsData import *
import socket
import threading
import atexit

# Register cleanup
atexit.register(lambda: prntlog.logger.stop())

port = 53
ip = '127.0.0.66'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind((ip, port))
    prntlog.success_message(f"\nTHE SERVER HAS STARTED!!!\nip: {ip}, port {port}\n")
except Exception as e:
    prntlog.error_message(f"ERROR BINDING TO {port}: {e}\n")
    exit(1)

while True:
    prntlog.debug_message("....the server is listening....")

    data, addr = sock.recvfrom(512)
    prntlog.info_message_timed(f" <-- Received data from {addr}")
    client_thread = threading.Thread(target=handle_client, args=(data, addr, sock))
    client_thread.start()




