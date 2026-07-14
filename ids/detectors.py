from scapy.all import IP, TCP, ICMP, ARP
import time
from collections import defaultdict

class BaseDetector:
    def __init__(self, config):
        self.config = config

    def process_packet(self, packet):
        raise NotImplementedError("Subclasses must implement process_packet")

class SynScanDetector(BaseDetector):
    def __init__(self, config):
        super().__init__(config)
        self.threshold = self.config.get('packet_threshold', 20)
        self.time_window = self.config.get('time_window', 5)
        # track {ip: [timestamps]}
        self.syn_counts = defaultdict(list)

    def process_packet(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Check for SYN flag set, ACK not set
            if packet[TCP].flags == 'S':
                src_ip = packet[IP].src
                current_time = time.time()
                
                # Cleanup old timestamps
                self.syn_counts[src_ip] = [t for t in self.syn_counts[src_ip] if current_time - t <= self.time_window]
                
                self.syn_counts[src_ip].append(current_time)
                
                if len(self.syn_counts[src_ip]) > self.threshold:
                    count = len(self.syn_counts[src_ip])
                    self.syn_counts[src_ip] = [] # Reset after detection to prevent flood of alerts
                    return {"type": "SYN Scan", "src_ip": src_ip, "count": count}
        return None

class IcmpFloodDetector(BaseDetector):
    def __init__(self, config):
        super().__init__(config)
        self.threshold = self.config.get('packet_threshold', 50)
        self.time_window = self.config.get('time_window', 5)
        self.icmp_counts = defaultdict(list)

    def process_packet(self, packet):
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            # ICMP Echo Request (type 8)
            if packet[ICMP].type == 8:
                src_ip = packet[IP].src
                current_time = time.time()
                
                self.icmp_counts[src_ip] = [t for t in self.icmp_counts[src_ip] if current_time - t <= self.time_window]
                self.icmp_counts[src_ip].append(current_time)
                
                if len(self.icmp_counts[src_ip]) > self.threshold:
                    count = len(self.icmp_counts[src_ip])
                    self.icmp_counts[src_ip] = []
                    return {"type": "ICMP Flood", "src_ip": src_ip, "count": count}
        return None

class ArpSpoofDetector(BaseDetector):
    def __init__(self, config):
        super().__init__(config)
        self.threshold = self.config.get('gratuitous_arp_threshold', 10)
        self.time_window = self.config.get('time_window', 5)
        self.ip_mac_mapping = {}
        self.gratuitous_counts = defaultdict(list)

    def process_packet(self, packet):
        if packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            
            # Detect duplicate IP-to-MAC (IP mapped to a different MAC previously)
            if src_ip in self.ip_mac_mapping:
                if self.ip_mac_mapping[src_ip] != src_mac:
                    # Anomaly: same IP, different MAC
                    # We might update it to avoid repeated alerts, or keep the old one depending on strategy
                    self.ip_mac_mapping[src_ip] = src_mac 
                    return {"type": "ARP Spoofing (Duplicate IP-to-MAC)", "src_ip": src_ip, "count": 1}
            else:
                self.ip_mac_mapping[src_ip] = src_mac

            # Detect gratuitous ARP floods (who-has or is-at to broadcast without being requested)
            # Gratuitous ARP: psrc == pdst or hwdest == broadcast
            if packet[ARP].psrc == packet[ARP].pdst:
                current_time = time.time()
                self.gratuitous_counts[src_ip] = [t for t in self.gratuitous_counts[src_ip] if current_time - t <= self.time_window]
                self.gratuitous_counts[src_ip].append(current_time)
                
                if len(self.gratuitous_counts[src_ip]) > self.threshold:
                    count = len(self.gratuitous_counts[src_ip])
                    self.gratuitous_counts[src_ip] = []
                    return {"type": "ARP Spoofing (Gratuitous Flood)", "src_ip": src_ip, "count": count}
        return None
