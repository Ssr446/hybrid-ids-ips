# Hybrid Network Intrusion Detection & Prevention System

A Python-based IDS/IPS utilizing Scapy for deep packet inspection, iptables for prevention, and Flask for API/Dashboard visualization.

## Features
- **Packet Sniffing**: Live capture or PCAP simulation mode.
- **Threat Detection**: Config-driven detection for SYN Scans, ICMP Floods, and ARP Spoofing anomalies.
- **Active Prevention**: Automatically drops offending IPs via `iptables` and manages an auto-expiring blocklist.
- **Alerting**: SMTP email and Discord Webhook integration.
- **Dashboard**: Premium UI to view live event feeds, threat statistics, and active blocklists.

## Setup Instructions

### 1. Local Development (Simulation Mode)
Simulation mode replays a synthetic PCAP file and avoids executing real `iptables` commands, allowing you to run it without root access on Windows, Mac, or standard Linux.

```bash
# Clone and enter the directory
git clone https://github.com/yourusername/cybersec-ids.git
cd cybersec-ids

# Create a virtual environment and install dependencies
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt

# Generate the synthetic simulation PCAP
python generate_pcap.py

# Run the app in simulation mode
SIMULATION_MODE=true python app.py
```
Open `http://localhost:5000` in your browser.

### 2. Free Hosting (Dashboard/API demo via Render)
You can deploy this project to Render's free tier to showcase the dashboard and API in simulation mode.

1. Push this repository to your GitHub account.
2. Sign up / Log in to [Render](https://render.com).
3. Go to the Dashboard and click **New +** -> **Web Service**.
4. Connect your GitHub repository.
5. Render will automatically detect the `render.yaml` blueprint. 
6. Apply the blueprint. You will be prompted to enter values for `SMTP_USER`, `SMTP_PASS`, and `DISCORD_WEBHOOK_URL` (you can leave these blank if you don't want alerts).
7. Once deployed, Render will provide a public URL to view your dashboard.

### 3. Full Live Deployment (Real Sniffing + iptables)
To use actual packet sniffing and `iptables` blocking, you must run this on a Linux machine with root privileges and raw socket access. We recommend using Oracle Cloud's Always Free tier.

1. **Create a VM**: Go to Oracle Cloud and create a Compute instance. Select the **Ampere A1** shape (Always Free) with Ubuntu Linux.
2. **Open Ports**: In the Oracle Cloud dashboard, go to your VCN's Security List and add an ingress rule for TCP port `5000`.
3. **SSH into the VM**:
   ```bash
   ssh ubuntu@<your-vm-ip>
   ```
4. **Install Dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y python3-pip python3-venv iptables
   ```
5. **Setup the App**:
   ```bash
   git clone https://github.com/yourusername/cybersec-ids.git
   cd cybersec-ids
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
6. **Run with Root Privileges**:
   ```bash
   # SIMULATION_MODE must be false or unset
   sudo ./venv/bin/python app.py
   ```
7. Access your live dashboard at `http://<your-vm-ip>:5000`.

## Architecture & Configuration
Edit `config.yaml` to tweak detection thresholds (e.g., packets/sec limits) and block expiration times. The architecture is modular: new detectors can be added by subclassing `BaseDetector` in `ids/detectors.py`.
