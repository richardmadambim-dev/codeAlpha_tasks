#Network Sniffer coodes that capture network traffic packets

import socket
import struct
print(socket.gethostname())

Host = "10.165.245.127"
print(Host)

#Raw socket: capture full IPv4 packets 
sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
sniffer.bind((Host,0))
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,3)
sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

names = {1: "ICMP", 6:"TCP", 17: "UDP"}
log = open("capture.text","w")
print("sniffer ready")

#This is a while loop
try:
    while 1:
        data, addr =sniffer.recvfrom(65535)
        #First 20 bytes = IP header
        ip = struct.unpack("!BBHHHBBH4s4s", data[:20])
        proto = names.get(ip[6], "other")
        size = ip[2]
        ttl = ip[5]
        src = socket.inet_ntoa(ip[8])
        dst =  socket.inet_ntoa(ip[9])

#Conditional statement
        if ip[6] in (6,17):
            payload = data[20 + (data[32]>> 4) * 4:]
            port = struct.unpack("!HH", data[20:24])
            line = f"{proto}  {src}:{port[0]} -> {dst}:{port[1]} | size {size} | ttl {ttl}"
        else:
            payload = data[28:]
            line = f"{proto} {src} -> {dst} | size {size} |ttl {ttl}"
            print(line)
            print("Payload:", payload[:50])
            log.write(line + "\n")
            log.write("Payload:" + str(payload[:50] ))
#Save and close the log file
except KeyboardInterrupt:
    print("Stopped")
    sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
    log.close()

