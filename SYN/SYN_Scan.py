from scapy.all import IP, ICMP,TCP, sr1
import sys
def icmp_probe(ip):
    icmp_packet = IP(dst=ip)/ICMP()
    resp_packet = sr1(icmp_packet, timeout=10)
    return resp_packet != None

def syn_scan(ip, port):
    syn_packet = IP(dst=ip)/TCP(dport=port, flags='S')
    resp_packet = sr1(syn_packet, timeout=4)
    if resp_packet == None:
        print(f"##Port {port} is close##")
    elif (resp_packet.getlayer('TCP').flags == 0x12):
        print(f"##Port {port} is open##")
    else:
        print("##Something wrong. Port get response but not with SYN, ACK packet##")
    return resp_packet

if __name__ == "__main__":
    ip = sys.argv[1]
    port = int(sys.argv[2])
    if icmp_probe(ip):
        syn_ack_packet = syn_scan(ip, port)
        try:
            syn_ack_packet.show()
        except AttributeError:
            pass
    else:
        print("###ICMP Probe Failed###")