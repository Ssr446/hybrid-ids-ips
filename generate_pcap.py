from scapy.all import Ether, IP, TCP, ICMP, ARP, wrpcap
import time

def generate_pcap():
    packets = []
    
    # 1. Normal traffic (background noise)
    for _ in range(10):
        packets.append(Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / IP(src="192.168.1.100", dst="8.8.8.8") / TCP(dport=80, flags="PA"))
    
    # 2. SYN Scan from 10.0.0.50 (needs > 20 packets to trigger based on default config)
    for port in range(1, 25):
        packets.append(Ether() / IP(src="10.0.0.50", dst="192.168.1.10") / TCP(dport=port, flags="S"))
    
    # Normal traffic gap
    packets.append(Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / TCP(dport=443, flags="PA"))
    
    # 3. ICMP Flood from 10.0.0.60 (needs > 50 packets)
    for _ in range(55):
        packets.append(Ether() / IP(src="10.0.0.60", dst="192.168.1.10") / ICMP(type=8))

    # 4. ARP Spoofing - Gratuitous flood from 10.0.0.70 (needs > 10 packets)
    for _ in range(15):
        packets.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="10.0.0.70", hwsrc="aa:bb:cc:11:22:33", pdst="10.0.0.70"))
        
    # 5. ARP Spoofing - Duplicate IP to MAC (192.168.1.1 mapped to two different MACs)
    packets.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="192.168.1.1", hwsrc="00:00:00:00:00:01", pdst="192.168.1.255"))
    packets.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="192.168.1.1", hwsrc="00:00:00:00:00:02", pdst="192.168.1.255"))

    wrpcap("simulation.pcap", packets)
    print("simulation.pcap generated successfully.")

if __name__ == "__main__":
    generate_pcap()
