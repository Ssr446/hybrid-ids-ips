import subprocess
import logging
import os
import time
import threading

logger = logging.getLogger(__name__)

# In-memory blocklist: {ip: expiration_timestamp}
blocklist = {}
blocklist_lock = threading.Lock()

def block_ip(ip, duration_minutes):
    expiration = time.time() + (duration_minutes * 60)
    
    with blocklist_lock:
        if ip in blocklist:
            blocklist[ip] = expiration # update expiration
            return False # already blocked
        
        blocklist[ip] = expiration
        
    simulation_mode = os.environ.get('SIMULATION_MODE', 'false').lower() == 'true'
    
    if simulation_mode:
        logger.info(f"SIMULATION: would block {ip} using iptables")
    else:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logger.info(f"Blocked {ip} using iptables")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block {ip} via iptables: {e}")
            with blocklist_lock:
                del blocklist[ip] # Revert on failure
            return False
        except FileNotFoundError:
            logger.error("iptables command not found. Ensure you are on Linux and have root privileges.")
            with blocklist_lock:
                del blocklist[ip]
            return False
            
    return True

def unblock_ip(ip):
    with blocklist_lock:
        if ip not in blocklist:
            return False
        del blocklist[ip]

    simulation_mode = os.environ.get('SIMULATION_MODE', 'false').lower() == 'true'
    
    if simulation_mode:
        logger.info(f"SIMULATION: would unblock {ip} using iptables")
    else:
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            logger.info(f"Unblocked {ip} using iptables")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock {ip} via iptables: {e}")
            return False
            
    return True

def get_blocklist():
    with blocklist_lock:
        current_time = time.time()
        # Filter out expired IPs just in case the cleanup thread hasn't run
        return {ip: exp for ip, exp in blocklist.items() if exp > current_time}

def cleanup_blocklist_thread():
    while True:
        current_time = time.time()
        expired_ips = []
        with blocklist_lock:
            for ip, exp in list(blocklist.items()):
                if exp <= current_time:
                    expired_ips.append(ip)
                    
        for ip in expired_ips:
            logger.info(f"Block duration expired for {ip}")
            unblock_ip(ip)
            
        time.sleep(10)

def start_cleanup_thread():
    t = threading.Thread(target=cleanup_blocklist_thread, daemon=True)
    t.start()
