#dnsServer.py
import logfromat as prntlog
import socket
import time


port = 53
ip = '127.0.0.66'
ascii_art = '''
╔╦╗╦ ╦╔═╗  ╔═╗╔═╗╦═╗╦  ╦╔═╗╦═╗  ╦ ╦╔═╗╔═╗  ╔═╗╔╦╗╔═╗╦═╗╔╦╗╔═╗╔╦╗
 ║ ╠═╣║╣   ╚═╗║╣ ╠╦╝╚╗╔╝║╣ ╠╦╝  ╠═╣╠═╣╚═╗  ╚═╗ ║ ╠═╣╠╦╝ ║ ║╣  ║║
 ╩ ╩ ╩╚═╝  ╚═╝╚═╝╩╚═ ╚╝ ╚═╝╩╚═  ╩ ╩╩ ╩╚═╝  ╚═╝ ╩ ╩ ╩╩╚═ ╩ ╚═╝═╩╝
'''

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind((ip, port))
    prntlog.success_message(f"\n{ascii_art}ip: {ip}, port {port}\n")
except Exception as e:
    prntlog.error_message(f"ERROR BINDING TO {port}: {e}\n")
    time.sleep(0.00001)
    exit(1)

while True:
    prntlog.debug_message("....the server is listening....")

    data, addr = sock.recvfrom(512)
    prntlog.info_message_timed(f" <-- Received data from {addr}")
    sock.sendto(b"ma3ak a el dns ya bash!", addr)    



