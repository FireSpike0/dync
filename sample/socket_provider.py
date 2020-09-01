#!/usr/bin/python3
import socket as sck


class AddressProvider():
    def get_ip(self):
        # your code
        pass


af = sck.AF_INET6
port = 51001

ap = AddressProvider()
s = sck.socket(af, sck.SOCK_DGRAM)
s.bind(('', port))

while True:
    data, addr = s.recvfrom(256)
    if not data:
        continue
    if data.decode('utf-8') == 'ip-request\n':
        s.sendto(ap.get_ip().encode('utf-8'), addr)
