import yaml
import logging
from ids.detectors import SynScanDetector, IcmpFloodDetector, ArpSpoofDetector
from ids.prevention import block_ip
from ids.alerting import send_alert
from ids.database import log_event

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(self, config_path="config.yaml"):
        self.config = self._load_config(config_path)
        self.detectors = self._initialize_detectors()
        self.block_duration = self.config.get('prevention', {}).get('block_duration_minutes', 10)

    def _load_config(self, config_path):
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config from {config_path}: {e}")
            # Fallback default config
            return {
                "detection": {
                    "syn_scan": {"packet_threshold": 20, "time_window": 5},
                    "icmp_flood": {"packet_threshold": 50, "time_window": 5},
                    "arp_spoof": {"gratuitous_arp_threshold": 10, "time_window": 5}
                },
                "prevention": {"block_duration_minutes": 10}
            }

    def _initialize_detectors(self):
        detection_config = self.config.get('detection', {})
        return [
            SynScanDetector(detection_config.get('syn_scan', {})),
            IcmpFloodDetector(detection_config.get('icmp_flood', {})),
            ArpSpoofDetector(detection_config.get('arp_spoof', {}))
        ]

    def process_packet(self, packet):
        for detector in self.detectors:
            try:
                alert = detector.process_packet(packet)
                if alert:
                    self._handle_alert(alert)
            except Exception as e:
                logger.error(f"Detector error: {e}")

    def _handle_alert(self, alert):
        src_ip = alert.get("src_ip")
        attack_type = alert.get("type")
        count = alert.get("count")

        logger.warning(f"ALERT: {attack_type} detected from {src_ip}")

        # 1. Block IP
        blocked = block_ip(src_ip, self.block_duration)
        action_taken = "Blocked" if blocked else "Failed to block"

        # 2. Log to DB
        log_event(src_ip, attack_type, action_taken, "High")

        # 3. Send Notifications
        send_alert(src_ip, attack_type, count)
