import pytest
from ids.detectors import SynScanDetector, IcmpFloodDetector, ArpSpoofDetector
from scapy.all import IP, TCP, ICMP, ARP, Ether

def test_syn_scan_detector():
    config = {'packet_threshold': 5, 'time_window': 5}
    detector = SynScanDetector(config)
    
    src_ip = "10.0.0.1"
    
    # Send 5 SYN packets (threshold is 5, so >5 triggers it)
    for port in range(10, 15):
        pkt = IP(src=src_ip, dst="192.168.1.1") / TCP(dport=port, flags="S")
        alert = detector.process_packet(pkt)
        assert alert is None
        
    # 6th packet should trigger alert
    pkt = IP(src=src_ip, dst="192.168.1.1") / TCP(dport=15, flags="S")
    alert = detector.process_packet(pkt)
    
    assert alert is not None
    assert alert['type'] == "SYN Scan"
    assert alert['src_ip'] == src_ip
    assert alert['count'] == 6

def test_icmp_flood_detector():
    config = {'packet_threshold': 10, 'time_window': 5}
    detector = IcmpFloodDetector(config)
    
    src_ip = "10.0.0.2"
    
    for _ in range(10):
        pkt = IP(src=src_ip, dst="192.168.1.1") / ICMP(type=8)
        alert = detector.process_packet(pkt)
        assert alert is None
        
    pkt = IP(src=src_ip, dst="192.168.1.1") / ICMP(type=8)
    alert = detector.process_packet(pkt)
    
    assert alert is not None
    assert alert['type'] == "ICMP Flood"
    assert alert['src_ip'] == src_ip
    assert alert['count'] == 11

def test_arp_spoof_duplicate_mac():
    config = {'gratuitous_arp_threshold': 5, 'time_window': 5}
    detector = ArpSpoofDetector(config)
    
    src_ip = "192.168.1.1"
    
    # First mapping
    pkt1 = ARP(psrc=src_ip, hwsrc="aa:bb:cc:dd:ee:01")
    alert1 = detector.process_packet(pkt1)
    assert alert1 is None
    
    # Second mapping, different MAC
    pkt2 = ARP(psrc=src_ip, hwsrc="aa:bb:cc:dd:ee:02")
    alert2 = detector.process_packet(pkt2)
    
    assert alert2 is not None
    assert "Duplicate IP-to-MAC" in alert2['type']
    assert alert2['src_ip'] == src_ip

def test_arp_spoof_gratuitous_flood():
    config = {'gratuitous_arp_threshold': 3, 'time_window': 5}
    detector = ArpSpoofDetector(config)
    
    src_ip = "10.0.0.3"
    
    for _ in range(3):
        pkt = ARP(psrc=src_ip, pdst=src_ip, hwsrc="11:22:33:44:55:66")
        alert = detector.process_packet(pkt)
        assert alert is None
        
    pkt = ARP(psrc=src_ip, pdst=src_ip, hwsrc="11:22:33:44:55:66")
    alert = detector.process_packet(pkt)
    
    assert alert is not None
    assert "Gratuitous Flood" in alert['type']
    assert alert['src_ip'] == src_ip
    assert alert['count'] == 4
