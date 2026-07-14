import logging
import os
from flask import Flask, render_template, jsonify, request
from ids.database import init_db, get_events, get_stats_24h
from ids.prevention import get_blocklist, unblock_ip, start_cleanup_thread
from ids.engine import DetectionEngine
from ids.sniffer import SnifferThread

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Initialize DB
init_db()

# Start background tasks
start_cleanup_thread()

engine = DetectionEngine()
sniffer_thread = SnifferThread(engine)
sniffer_thread.start()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/events', methods=['GET'])
def api_events():
    limit = int(request.args.get('limit', 50))
    offset = int(request.args.get('offset', 0))
    events = get_events(limit=limit, offset=offset)
    return jsonify(events)

@app.route('/api/blocklist', methods=['GET'])
def api_blocklist():
    bl = get_blocklist()
    # format for json
    formatted_bl = [{"ip": ip, "expires_at": exp} for ip, exp in bl.items()]
    return jsonify(formatted_bl)

@app.route('/api/blocklist/unblock/<ip>', methods=['POST'])
def api_unblock(ip):
    success = unblock_ip(ip)
    if success:
        return jsonify({"status": "success", "message": f"{ip} unblocked"}), 200
    else:
        return jsonify({"status": "error", "message": f"{ip} not found in blocklist or error"}), 404

@app.route('/api/stats', methods=['GET'])
def api_stats():
    stats = get_stats_24h()
    return jsonify(stats)

if __name__ == '__main__':
    # When running directly (e.g. for dev)
    app.run(host='0.0.0.0', port=5000, debug=False) 
    # Note: debug=True with Flask's auto-reloader will spawn the background threads twice.
