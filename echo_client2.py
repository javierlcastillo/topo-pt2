import socket

def main():
    host = '192.168.56.101'
    port = 3000
    
    print("---- UDP Client ----")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b'hello world to UDP server', (host, port))
        data, _ = s.recvfrom(1024)
        print('Received (UDP): ', data.decode())

    print("---- TCP Client ----")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: 
        s.connect((host, port))
        s.sendall(b'hello world to TCP server')
        data = s.recv(1024)
        print('Received (TCP): ', data.decode())

if __name__ == '__main__':
    main()
