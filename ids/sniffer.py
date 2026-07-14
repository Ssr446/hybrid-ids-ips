from scapy.all import sniff, rdpcap
import os
import logging
import threading
from ids.engine import DetectionEngine
import time

logger = logging.getLogger(__name__)

class SnifferThread(threading.Thread):
    def __init__(self, engine, interface=None):
        super().__init__(daemon=True)
        self.engine = engine
        self.interface = interface
        self.simulation_mode = os.environ.get('SIMULATION_MODE', 'false').lower() == 'true'
        self.running = True

    def run(self):
        logger.info(f"Starting sniffer. Simulation mode: {self.simulation_mode}")
        
        if self.simulation_mode:
            self._run_simulation()
        else:
            self._run_live()

    def _run_simulation(self):
        pcap_file = "simulation.pcap"
        while self.running:
            if not os.path.exists(pcap_file):
                logger.error(f"Simulation file {pcap_file} not found. Sniffer paused.")
                time.sleep(5)
                continue
            
            try:
                packets = rdpcap(pcap_file)
                logger.info(f"Replaying {len(packets)} packets from {pcap_file}")
                for pkt in packets:
                    if not self.running:
                        break
                    self.engine.process_packet(pkt)
                    time.sleep(0.01) # Small delay to simulate live traffic flow and allow UI to poll
                
                logger.info("Finished replaying pcap, looping...")
                time.sleep(2) # Pause before looping again
            except Exception as e:
                logger.error(f"Error reading pcap: {e}")
                time.sleep(5)

    def _run_live(self):
        def packet_handler(pkt):
            self.engine.process_packet(pkt)

        try:
            logger.info(f"Sniffing on interface: {self.interface or 'default'}")
            sniff(iface=self.interface, prn=packet_handler, store=0)
        except PermissionError:
            logger.error("Permission denied to open raw sockets. Are you running as root?")
        except Exception as e:
            logger.error(f"Sniffer error: {e}")
