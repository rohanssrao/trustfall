import socket, ssl

host = "example.com"
ip = socket.gethostbyname(host)  # IPv4 only

ctx = ssl._create_unverified_context()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect((ip, 443))

t = ctx.wrap_socket(s, server_hostname=host)
t.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
print(t.recv(4096))
