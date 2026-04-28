from scapy.all import sniff

def processPacket(packet):
    srcIP = packet["IP"].src
    desIP = packet["IP"].dst
    try:
        if packet.getlayer('TCP').flags == 0x29:
            print(f"Probably XMas Scan Detected. Machine with IP {srcIP} try to scan machine with IP {desIP}")
    except AttributeError:
        pass
    

print("Start Scan")
try:
    sniff(count=0, filter = "ip and tcp", store = 0, prn = processPacket)
except KeyboardInterrupt:
    print("End Scan")
