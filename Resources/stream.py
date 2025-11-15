#!/usr/bin/python3

import socket

# This can also be accomplished by using s = socket.socket() due to AF_INET and SOCK_STREAM being defaults
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ipaddr = '127.0.0.1'
port = 1111

s.connect((ipaddr, port))

# To send a string as a bytes-like object, add the prefix b to the string. \n is used to go to the next line (hit enter)
s.send(b'Message\n')

# It is recommended that the buffersize used with recvfrom is a power of 2 and not a very large number of bits
data, conn = s.recvfrom(1024)

# In order to receive a message that is sent as a bytes-like-object you must decode into utf-8 (default)
print(data.decode('utf-8'))

s.close()